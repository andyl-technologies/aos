//! Runs the actual refreshed proofs and local Root3 append and send.
//!
//! Every receiving stage borrows the same Initial under its short L/U interval.
//! Native transport, preparation, append and writes run after that interval.
//! Entered bodies retain their primary result before independently owed posts.

use super::{Action, Error, First, RootOwnedInitialCurrentAttemptV1, Stage, frame};
use crate::normal_root::ProductionNormalRootStartupV1;

impl RootOwnedInitialCurrentAttemptV1<'_, '_, '_> {
    pub(super) fn receive_use_refresh_and_admitted_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        signer_uid: u32,
        socket_gid: u32,
    ) -> Result<(), Error> {
        self.receive_use_source_query_once_v1(startup)?;
        self.receive_use_source_exchange_once_v1(startup, signer_uid, socket_gid)?;
        self.receive_use_cache_proof_once_v1(startup)?;
        self.receive_use_admitted_once_v1(startup)
    }

    fn receive_use_source_query_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        self.drive_v1(startup, Stage::UseQueryEntry, 97)?;
        let returned = self.native.as_mut().ok_or(Error::Original)?
            .encode_use_source_query_once_v1().map_err(Action::Query);
        self.record_v1(98, returned)?;
        let returned = self.native.as_ref().ok_or(Error::Original)?
            .require_use_source_query_complete_v1().map_err(Action::Query);
        self.record_v1(99, returned)
    }

    fn receive_use_source_exchange_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        signer_uid: u32,
        socket_gid: u32,
    ) -> Result<(), Error> {
        // A failed fixed entry owes no body/post scope.
        self.drive_v1(startup, Stage::UseExchangeEntry, 100)?;
        let returned = self.native.as_mut().ok_or(Error::Original)?
            .exchange_use_source_once_v1(signer_uid, socket_gid).map_err(Action::Exchange);
        let body = self.record_v1(101, returned);
        if let Some(native) = &mut self.native {
            native.observe_use_source_exchange_native_posts_once_v1();
        }
        self.latch_native_v1();
        let armed = self.drive_v1(startup, Stage::UseExchangePost, 102);
        if armed.is_err() {
            if let Some(native) = &mut self.native {
                native.refuse_use_source_exchange_post_arm_once_v1();
            }
        }
        if let Some(native) = &mut self.native {
            native.observe_use_source_exchange_post_once_v1();
        }
        self.latch_native_v1();
        body?;
        armed?;
        let returned = self.native.as_ref().ok_or(Error::Original)?
            .require_use_source_exchange_complete_v1().map_err(Action::Exchange);
        self.record_v1(103, returned)
    }

    fn receive_use_cache_proof_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        self.drive_v1(startup, Stage::UseCacheFixed, 104)?;
        let body = self.receive_use_cache_frame_v1(startup);
        self.latch_native_v1();
        if matches!(self.actions[105], Some(Err(_))) {
            self.first.get_or_insert(First::Action(105));
        }
        // Fixed admission owns these posts even if frame preparation failed.
        if let Some(native) = &mut self.native {
            native.observe_use_cache_proof_native_posts_once_v1();
        }
        self.latch_native_v1();
        let armed = self.drive_v1(startup, Stage::UseCachePost, 108);
        if armed.is_err() {
            if let Some(native) = &mut self.native {
                native.refuse_use_cache_proof_post_arm_once_v1();
            }
        }
        if let Some(native) = &mut self.native {
            native.observe_use_cache_proof_post_once_v1();
        }
        self.latch_native_v1();
        body?;
        armed?;
        let returned = self.native.as_ref().ok_or(Error::Original)?
            .require_use_cache_proof_complete_v1().map_err(Action::Cache);
        self.record_v1(109, returned)
    }

    fn receive_use_cache_frame_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        let native = self.native.as_mut().ok_or(Error::Original)?;
        let mut cut = match native.borrow_use_cache_proof_once_v1() {
            Ok(cut) => cut,
            Err(error) => {
                self.actions[105] = Some(Err(Action::Cache(error)));
                return Err(Error::Open);
            }
        };
        let received = match cut.borrow_subject_once_v1() {
            Ok(mut subject) => frame::receive_frame_v1(
                startup, &mut subject, &mut self.frame, &mut self.first,
            ),
            Err(error) => {
                self.actions[106] = Some(Err(Action::Operation(error)));
                Err(Error::Ready)
            }
        };
        if received.is_err() {
            self.first.get_or_insert(if cut.failure_v1().is_some() {
                First::Native
            } else {
                First::Action(106)
            });
            return received;
        }
        self.actions[107] = Some(cut.finish_once_v1().map_err(Action::Cache));
        if matches!(self.actions[107], Some(Err(_))) {
            self.first.get_or_insert(if cut.failure_v1().is_some() {
                First::Native
            } else {
                First::Action(107)
            });
            return Err(Error::Open);
        }
        Ok(())
    }

    fn receive_use_admitted_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        self.drive_v1(startup, Stage::UseAdmittedFixed, 110)?;
        // Refusal before the append arm creates no owed append scope.
        self.drive_v1(startup, Stage::UseAdmittedAppend, 111)?;
        let body = self.receive_use_admitted_body_v1(startup);
        self.latch_native_v1();
        if let Some(native) = &mut self.native {
            native.observe_use_admitted_append_posts_once_v1();
        }
        self.latch_native_v1();
        body?;
        let returned = self.native.as_mut().ok_or(Error::Original)?
            .frame_use_admitted_once_v1().map_err(Action::UseAdmitted);
        self.record_v1(115, returned)?;
        self.drive_v1(startup, Stage::UseAdmittedSend, 116)?;
        // Native send retains the write and all independently owed send posts.
        let returned = self.native.as_mut().ok_or(Error::Original)?
            .send_use_admitted_once_v1().map_err(Action::UseAdmitted);
        self.record_v1(117, returned)?;
        let returned = self.native.as_ref().ok_or(Error::Original)?
            .require_use_admitted_complete_v1().map_err(Action::UseAdmitted);
        self.record_v1(118, returned)
    }

    fn receive_use_admitted_body_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        let returned = self.native.as_mut().ok_or(Error::Original)?
            .prepare_use_admitted_once_v1().map_err(Action::UseAdmitted);
        self.record_v1(112, returned)?;
        self.drive_v1(startup, Stage::UseAdmittedCrossing, 113)?;
        let returned = self.native.as_mut().ok_or(Error::Original)?
            .append_use_admitted_once_v1().map_err(Action::UseAdmitted);
        self.record_v1(114, returned)
    }
}
