//! Brackets the same held helper's bounded NV exchanges with Source currentness.
//!
//! Replies remain in the native owner. Returned projections are comparison DATA;
//! Security owns approved intent, public-area/Name validation and any decision
//! to perform the sole initial Extend or publish a canonical checkpoint.

use aos_sandbox_broker::fixed_tpm_helper_wire::HelperObservationV1;

use super::*;

impl Method46InitialTpmHelperDrivingLoanV1<'_> {
    /// Reads initial public-area/value DATA through this same authenticated helper.
    ///
    /// # Errors
    /// Refuses missing original AUTH, reentry, changed Source, elapsed native cut,
    /// transport, child, record-subject or framing failure. Actual native replies
    /// and failed prefixes stay in the Source; no caller observation is adopted.
    pub fn read_initial_nv_once_v1(
        &mut self,
    ) -> Result<HelperObservationV1, Method46InitialStartupClosedV1> {
        require_current(self.startup)?;
        let action = self.native.prepare_initial_read_once_v1();
        observe_after(self.startup, action)?;
        self.drive_prepared_nv_data()
    }

    /// Performs at most one initial Extend through the original held helper.
    ///
    /// The input is DATA, never an approval receipt. The protected Security
    /// owner must derive it from its resident verified intent and independently
    /// compare the original first observation before calling this operation.
    /// A failure preserves ambiguous effects and grants no retry permission.
    ///
    /// # Errors
    /// Refuses missing initial Read, repeated Extend, sentinel input, changed
    /// Source, native transport/custody failure or malformed correlated reply.
    pub fn extend_initial_nv_once_v1(
        &mut self,
        input: [u8; 32],
    ) -> Result<HelperObservationV1, Method46InitialStartupClosedV1> {
        require_current(self.startup)?;
        let action = self.native.prepare_initial_extend_once_v1(input);
        observe_after(self.startup, action)?;
        self.drive_prepared_nv_data()
    }

    /// Reads final DATA after the original first Read or sole initial Extend.
    ///
    /// # Errors
    /// Refuses missing predecessor, reentry, changed Source, elapsed native cut,
    /// transport/child/subject failure or noncanonical reply. Success supplies
    /// no cleanup, checkpoint-publication or ordinary runtime-floor authority.
    pub fn read_final_nv_once_v1(
        &mut self,
    ) -> Result<HelperObservationV1, Method46InitialStartupClosedV1> {
        require_current(self.startup)?;
        let action = self.native.prepare_final_read_once_v1();
        observe_after(self.startup, action)?;
        self.drive_prepared_nv_data()
    }

    /// Closes this helper's TPM context and reaps the original child once.
    ///
    /// The close ACK remains resident and is admitted as a distinct record from
    /// the same original child. The original supervisor must then reach clean
    /// exit zero with no cause or cleanup debt. Ambiguous failure grants no
    /// whole-unit drain or retry claim; checkpoint authority remains separate.
    ///
    /// # Errors
    /// Refuses missing final Read, reentry, changed Source, elapsed cut, native
    /// transport or child/record admission failure. Failed prefixes remain held.
    pub fn close_and_reap_initial_helper_once_v1(
        &mut self,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        require_current(self.startup)?;
        let action = self.native.prepare_initial_close_once_v1();
        observe_after(self.startup, action)?;
        self.drive_prepared_exchange()?;

        let action = self.native.wait_initial_finish_once_v1();
        observe_after(self.startup, action)?;
        let action = self.native.send_initial_finish_once_v1();
        observe_after(self.startup, action)?;

        loop {
            // Native custody permits at most its fixed prepaid turn count.
            let action = self.native.advance_initial_cleanup_once_v1();
            let complete = action.as_ref().copied().unwrap_or(false);
            observe_after(self.startup, action.map(|_| ()))?;
            if complete {
                self.helper_retired = true;
                return Ok(());
            }
            let action = self.native.wait_initial_cleanup_once_v1();
            observe_after(self.startup, action)?;
        }
    }

    fn drive_prepared_exchange(&mut self) -> Result<(), Method46InitialStartupClosedV1> {
        let action = self.native.wait_nv_send_once_v1();
        observe_after(self.startup, action)?;

        // Readiness may have waited. Compare actual main names/metadata against
        // the original replayed file immediately before the request effect.
        let before = self.begin_nv_main();
        let action = (|| {
            before?;
            let action = self.native.send_nv_once_v1();
            observe_after(self.startup, action)?;

            let action = self.native.wait_nv_receive_once_v1();
            observe_after(self.startup, action)?;
            let action = self.native.receive_nv_once_v1();
            observe_after(self.startup, action)
        })();
        let after = self.finish_nv_main_after_owed();
        if action.is_err() || after.is_err() {
            Err(self.startup.fail(First::TpmHelperBirth))
        } else {
            Ok(())
        }
    }

    fn begin_nv_main(&self) -> Result<(), Method46InitialStartupClosedV1> {
        require_current(self.startup)?;
        let result = (|| {
            self.startup
                .body
                .as_ref()
                .ok_or(self.startup.closed)?
                .main_writer
                .try_borrow_mut()
                .map_err(|_| self.startup.closed)?
                .begin_initial_nv_main_once()
                .map_err(|_| self.startup.closed)
        })();
        let after = require_current(self.startup);
        if result.is_err() || after.is_err() {
            Err(self.startup.fail(First::MainWriter))
        } else {
            Ok(())
        }
    }

    fn finish_nv_main_after_owed(&self) -> Result<(), Method46InitialStartupClosedV1> {
        // No successful-currentness prerequisite can erase the native post.
        let result = (|| {
            self.startup
                .body
                .as_ref()
                .ok_or(self.startup.closed)?
                .main_writer
                .try_borrow_mut()
                .map_err(|_| self.startup.closed)?
                .finish_initial_nv_main_after_owed()
                .map_err(|_| self.startup.closed)
        })();
        let after = require_current(self.startup);
        if result.is_err() || after.is_err() {
            Err(self.startup.fail(First::MainWriter))
        } else {
            Ok(())
        }
    }

    fn drive_prepared_nv_data(
        &mut self,
    ) -> Result<HelperObservationV1, Method46InitialStartupClosedV1> {
        self.drive_prepared_exchange()?;

        let observed = self
            .native
            .nv_observation_data_v1()
            .map_err(|_| self.startup.fail(First::TpmHelperBirth))?;
        Ok(HelperObservationV1 {
            name: observed.name,
            name_algorithm: observed.name_algorithm,
            attributes: observed.attributes,
            size: observed.size,
            policy_length: observed.policy_length,
            value: observed.value,
        })
    }
}
