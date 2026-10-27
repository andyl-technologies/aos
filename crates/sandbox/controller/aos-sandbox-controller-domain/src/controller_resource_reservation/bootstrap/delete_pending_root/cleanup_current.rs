//! Sends completed Network9/Host3 receipts on the saved Bank's actual D flight.

use super::*;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;

impl ControllerResourceBankOpeningV1 {
    /// Sends actual cleanup receipt coordinates for independent Root comparison.
    ///
    /// Borrowed packets remain historical DATA. The genuine completed Network
    /// native owner, fresh Host query disposal, committed Source/C and actual
    /// Root client select this entry; Root independently authenticates them.
    ///
    /// # Errors
    /// Refuses changed owners, incomplete queries, reentry, original expiry,
    /// financial refusal or any native/stream post failure. No Mount or Storage
    /// effect is authorized by a successful send.
    #[doc(hidden)]
    pub fn send_delete_cleanup_current_once_v4(
        &self,
        pending: &mut crate::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut ControllerDeletePendingRootClientOriginalV2<'_>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        network: (&[u8; 64], &AuthenticatedBrokerMethodOutcomeV1),
        host: (&[u8; 64], &AuthenticatedBrokerMethodOutcomeV1),
    ) -> Result<(), ResourceReservationErrorV1> {
        client
            .inner
            .require_profile_v2(profile)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        pending
            .send_cleanup_current_once_v4(&mut client.inner, controller, launch, network, host)
            .map_err(Into::into)
    }
}
