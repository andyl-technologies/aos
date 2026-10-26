//! Borrows the original private credential only for the closed initial helper.
//!
//! There is no key getter, caller buffer, callback or selectable channel. The
//! same credential owner retains its zeroizing readback and terminal posts.

use aos_sandbox_broker::fixed_initial_tpm_helper_birth::{
    InitialTpmHelperBirthClosedV1, InitialTpmHelperDrivingLoanV1,
};

use super::*;

impl InitialCredentialsOriginalV1 {
    /// Borrows the original private slot only for the admitted native carrier.
    ///
    /// # Errors
    /// Refuses reentry, incomplete or ended credentials, missing private bytes,
    /// wrong width, or the closed helper's actual native authentication refusal.
    pub(in crate::method46_initial_startup) fn transmit_held_helper_auth_once(
        &mut self,
        helper: &mut InitialTpmHelperDrivingLoanV1<'_>,
    ) -> Result<(), InitialTpmHelperBirthClosedV1> {
        if std::mem::replace(&mut self.helper_auth_attempted, true)
            || !self.admitted_before_post()
            || !self.selected[1]
        {
            return Err(InitialTpmHelperBirthClosedV1);
        }

        let held = self.credentials[1].bytes[0]
            .as_deref()
            .ok_or(InitialTpmHelperBirthClosedV1)?;
        let auth: &[u8; 32] = held
            .as_slice()
            .try_into()
            .map_err(|_| InitialTpmHelperBirthClosedV1)?;
        helper.send_held_auth_once_v1(auth)
    }
}
