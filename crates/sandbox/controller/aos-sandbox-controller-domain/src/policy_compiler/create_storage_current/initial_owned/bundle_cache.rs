//! Preserves genuine Bundle typed framing and nested Initial Cache custody.
//!
//! Bundle posts are owed only after the same parsed frame enters typed receiving.
//! Cache posts are owed after fixed admission, including frame preparation failure.
//! Neither scoped loan lends a replacement stream, completed role or phase DATA.

use super::{Action, Error, First, RootOwnedInitialCurrentAttemptV1, Stage, frame};
use crate::normal_root::ProductionNormalRootStartupV1;

impl RootOwnedInitialCurrentAttemptV1<'_, '_, '_> {
    /// Verifies the original Bundle through a genuine same-frame typed stage.
    ///
    /// # Errors
    /// Retains fixed/framing/typed refusal before post entry, or actual decoder,
    /// verification and independently owed native, peer or clock refusal.
    pub(super) fn receive_bundle_ownership_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        self.drive_v1(startup, Stage::BundleFixed, 41)?;
        let admitted = self.receive_bundle_frame_v1(startup);
        self.latch_native_v1();
        if admitted.is_err() {
            if matches!(self.actions[42], Some(Err(_))) {
                self.first.get_or_insert(First::Action(42));
            }
            return admitted;
        }
        // Only a real successful typed call reaches this scope. Verification
        // refusal is already parked and cannot suppress independent posts.
        if let Some(native) = &mut self.native {
            native.observe_initial_bundle_ownership_native_posts_once_v1();
        }
        self.latch_native_v1();
        let armed = self.drive_v1(startup, Stage::BundlePost, 45);
        if armed.is_err() {
            if let Some(native) = &mut self.native {
                native.refuse_initial_bundle_ownership_post_arm_once_v1();
            }
        }
        if let Some(native) = &mut self.native {
            native.observe_initial_bundle_ownership_post_once_v1();
        }
        self.latch_native_v1();
        if matches!(self.actions[44], Some(Err(_))) {
            return Err(Error::Open);
        }
        armed?;
        let returned = self
            .native
            .as_ref()
            .ok_or(Error::Original)?
            .require_initial_bundle_ownership_complete_v1()
            .map_err(Action::Bundle);
        self.record_v1(46, returned)
    }

    fn receive_bundle_frame_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        let native = self.native.as_mut().ok_or(Error::Original)?;
        let mut cut = match native.borrow_initial_bundle_ownership_once_v1() {
            Ok(cut) => cut,
            Err(error) => {
                self.actions[42] = Some(Err(Action::Bundle(error)));
                // The outer scope resolves the real native source after this
                // temporary factory Result and its exclusive loan have ended.
                return Err(Error::Open);
            }
        };
        self.actions[43] = Some(startup.begin_owned_current_bundle_typed_v1(&mut cut));
        if matches!(self.actions[43], Some(Err(_))) {
            self.first.get_or_insert(if cut.failure_v1().is_some() {
                First::Native
            } else {
                First::Action(43)
            });
            return Err(Error::Open);
        }
        // This SAME parsed cut survives the actual short L/U receiving call.
        self.actions[44] = Some(cut.verify_once_v1().map_err(Action::Bundle));
        if matches!(self.actions[44], Some(Err(_))) {
            self.first.get_or_insert(if cut.failure_v1().is_some() {
                First::Native
            } else {
                First::Action(44)
            });
        }
        Ok(())
    }

    /// Receives the original forwarded proof before finishing Root's signer half.
    ///
    /// # Errors
    /// Retains actual fixed, frame preparation, subject/stream, forwarded proof,
    /// independent signer or post refusal while all three originals stay owned.
    pub(super) fn receive_cache_proof_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        self.drive_v1(startup, Stage::CacheFixed, 47)?;
        let body = self.receive_cache_frame_v1(startup);
        self.latch_native_v1();
        if matches!(self.actions[48], Some(Err(_))) {
            self.first.get_or_insert(First::Action(48));
        }
        // Factory, Root-half, invitation and receive failures all owe these
        // posts because the actual fixed admission already succeeded.
        if let Some(native) = &mut self.native {
            native.observe_initial_cache_proof_native_posts_once_v1();
        }
        self.latch_native_v1();
        let armed = self.drive_v1(startup, Stage::CachePost, 51);
        if armed.is_err() {
            if let Some(native) = &mut self.native {
                native.refuse_initial_cache_proof_post_arm_once_v1();
            }
        }
        if let Some(native) = &mut self.native {
            native.observe_initial_cache_proof_post_once_v1();
        }
        self.latch_native_v1();
        body?;
        armed?;
        let returned = self
            .native
            .as_ref()
            .ok_or(Error::Original)?
            .require_initial_cache_proof_complete_v1()
            .map_err(Action::Cache);
        self.record_v1(52, returned)
    }

    fn receive_cache_frame_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        let native = self.native.as_mut().ok_or(Error::Original)?;
        let mut cut = match native.borrow_initial_cache_proof_once_v1() {
            Ok(cut) => cut,
            Err(error) => {
                self.actions[48] = Some(Err(Action::Cache(error)));
                return Err(Error::Open);
            }
        };
        let received = match cut.borrow_subject_once_v1() {
            Ok(mut subject) => {
                frame::receive_frame_v1(startup, &mut subject, &mut self.frame, &mut self.first)
            }
            Err(error) => {
                self.actions[49] = Some(Err(Action::Operation(error)));
                Err(Error::Ready)
            }
        };
        // The nested subject loan has ended. Its retained cause precedes the
        // independent signer finish, and its native buffers remain on Cache.
        if received.is_err() {
            self.first.get_or_insert(if cut.failure_v1().is_some() {
                First::Native
            } else {
                First::Action(49)
            });
            return received;
        }
        self.actions[50] = Some(cut.finish_once_v1().map_err(Action::Cache));
        if matches!(self.actions[50], Some(Err(_))) {
            self.first.get_or_insert(if cut.failure_v1().is_some() {
                First::Native
            } else {
                First::Action(50)
            });
            return Err(Error::Open);
        }
        Ok(())
    }
}
