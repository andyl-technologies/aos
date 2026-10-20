//! Lends only cursor8's completed Network9 successor from the saved Bank.

use super::*;

impl ControllerResourceBankOpeningV1 {
    /// Borrows a fresh Host3 query after the same actual Network9 completed.
    ///
    /// The SDK native position only compares to the original already retained
    /// on Pending. The actual committed Source/C and Root interval authorize
    /// entry; old planning or preaccept challenges cannot select this branch.
    ///
    /// # Errors
    /// Refuses incomplete Network9, changed originals, wrong Root cursor,
    /// stale authority or same-Source construction/native funding failure.
    #[doc(hidden)]
    pub fn borrow_delete_host_confirmation_once_v4<'turn, 'scope, 'original, 'profile>(
        &'turn self,
        pending: &'turn mut crate::ControllerDeletePendingOriginalV2<'scope, 'original>,
        client: &'turn mut ControllerDeletePendingRootClientOriginalV2<'profile>,
        controller: &'turn mut Journal,
        profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
        transcript: &aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1,
        shape: crate::DeleteInventorySecurityShapeDataV1,
        completed_network: &[u8; 64],
        upper_bytes: usize,
    ) -> Result<
        crate::DeleteInventorySessionAppendOriginalV1<
            'turn,
            'turn,
            'scope,
            'original,
            'scope,
            'profile,
        >,
        ResourceReservationErrorV1,
    > {
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        pending
            .borrow_host_confirmation_once_v4(
                &mut client.inner,
                controller,
                launch,
                profile.lower_original_v1(),
                transcript,
                shape,
                completed_network,
                upper_bytes,
            )
            .map_err(Into::into)
    }
}
