//! Preserves the distinct Trust and Initial Source admission/post frontiers.
//!
//! Trust allocates only after fixed admission and enters its independently owed
//! scope only after the late receiving check. The query has no native posts.
//! Source exchange owes its own posts only after actual fixed admission. Slow
//! native work stays outside the short same-original Initial/L/U arm slots.

use super::{Action, Error, RootOwnedInitialCurrentAttemptV1, Stage};
use crate::normal_root::ProductionNormalRootStartupV1;

impl RootOwnedInitialCurrentAttemptV1<'_, '_, '_> {
    /// Captures genuine Ownership trust without advancing its post scope early.
    ///
    /// # Errors
    /// Retains actual fixed, construction, late-entry, capture, typed, decoder
    /// or independently owed post refusal on the same owning programme.
    pub(super) fn receive_trust_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        self.drive_v1(startup, Stage::TrustFixed, 25)?;
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .construct_initial_trust_once_v1()
            .map_err(Action::Trust);
        self.record_v1(26, returned)?;

        // This late original-receiving check precedes the old unconditional
        // post scope. Its refusal must not invent native, peer or clock IO.
        let entered = self.drive_v1(startup, Stage::TrustEntry, 27);
        if entered.is_err() {
            if let Some(native) = &mut self.native {
                native.refuse_initial_trust_capture_entry_once_v1();
            }
            return entered;
        }

        let body = self.receive_trust_body_v1(startup);
        if let Some(native) = &mut self.native {
            native.observe_initial_trust_native_posts_once_v1();
        }
        self.latch_native_v1();
        let armed = self.drive_v1(startup, Stage::TrustPost, 31);
        if armed.is_err() {
            if let Some(native) = &mut self.native {
                native.refuse_initial_trust_post_arm_once_v1();
            }
        }
        if let Some(native) = &mut self.native {
            native.observe_initial_trust_post_once_v1();
        }
        self.latch_native_v1();
        body?;
        armed?;
        let returned = self
            .native
            .as_ref()
            .ok_or(Error::Original)?
            .require_initial_trust_complete_v1()
            .map_err(Action::Trust);
        self.record_v1(32, returned)
    }

    fn receive_trust_body_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .capture_initial_trust_credentials_once_v1()
            .map_err(Action::Trust);
        self.record_v1(28, returned)?;
        self.drive_v1(startup, Stage::TrustTyped, 29)?;
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .decode_initial_trust_once_v1()
            .map_err(Action::Trust);
        self.record_v1(30, returned)
    }

    /// Constructs only the genuine Initial query after actual Trust completion.
    ///
    /// # Errors
    /// Retains the real receiving, canonical encoding or same-record/held-receipt
    /// correlation refusal. This query stage performs no native post or clock.
    pub(super) fn receive_source_query_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        self.drive_v1(startup, Stage::QueryEntry, 33)?;
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .encode_initial_source_query_once_v1()
            .map_err(Action::Query);
        self.record_v1(34, returned)?;
        let returned = self
            .native
            .as_ref()
            .ok_or(Error::Original)?
            .require_initial_source_query_complete_v1()
            .map_err(Action::Query);
        self.record_v1(35, returned)
    }

    /// Exchanges Initial Source only inside its genuinely admitted fixed scope.
    ///
    /// # Errors
    /// Retains actual fixed, native socket, clock, framing, signature, query or
    /// independent post refusal. UID/GID are the old socket expectation DATA.
    pub(super) fn receive_source_exchange_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        signer_uid: u32,
        socket_gid: u32,
    ) -> Result<(), Error> {
        // Old fixed denial ends before this purpose's native post scope.
        self.drive_v1(startup, Stage::ExchangeEntry, 36)?;
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .exchange_initial_source_once_v1(signer_uid, socket_gid)
            .map_err(Action::Exchange);
        let body = self.record_v1(37, returned);
        if let Some(native) = &mut self.native {
            native.observe_initial_source_exchange_native_posts_once_v1();
        }
        self.latch_native_v1();
        let armed = self.drive_v1(startup, Stage::ExchangePost, 38);
        if armed.is_err() {
            if let Some(native) = &mut self.native {
                native.refuse_initial_source_exchange_post_arm_once_v1();
            }
        }
        if let Some(native) = &mut self.native {
            native.observe_initial_source_exchange_post_once_v1();
        }
        self.latch_native_v1();
        body?;
        armed?;
        let returned = self
            .native
            .as_ref()
            .ok_or(Error::Original)?
            .require_initial_source_exchange_complete_v1()
            .map_err(Action::Exchange);
        self.record_v1(39, returned)
    }
}
