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

    fn drive_prepared_nv_data(
        &mut self,
    ) -> Result<HelperObservationV1, Method46InitialStartupClosedV1> {
        // Each wait's independent Source post precedes the next native effect.
        // A failed action still owes that same Source observation.
        let action = self.native.wait_nv_send_once_v1();
        observe_after(self.startup, action)?;
        let action = self.native.send_nv_once_v1();
        observe_after(self.startup, action)?;

        let action = self.native.wait_nv_receive_once_v1();
        observe_after(self.startup, action)?;
        let action = self.native.receive_nv_once_v1();
        observe_after(self.startup, action)?;

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
