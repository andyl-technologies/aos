//! Projects final physical receipts onto the same held Source/C17 continuation.

use super::*;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_sandbox_protocol::domain_ledger::delete_root::completion::DeleteRootSourceCompletionDataV4;

/// Retains the original Source/C17 disposition through actual upper disposal.
///
/// This token is created only after the same Root's ACK, positive EOF, live
/// invocation and all independent Source/Root/C posts have completed.
#[doc(hidden)]
#[must_use = "dispose the completed collection before settling the original Source/C17"]
pub struct ControllerDeleteFinalDisposalOriginalV4<'disposal> {
    native: crate::journal::SourceDeleteCompletionDisposalOriginalV4<'disposal>,
}

impl ControllerDeleteFinalDisposalOriginalV4<'_> {
    /// Settles the original claim after the completed collection is dropped.
    pub fn complete_after_upper_disposal_v4(self) {
        self.native.complete_after_upper_disposal_v4();
    }
}

impl ControllerResourceBankOpeningV1 {
    /// Verifies final ACK and actual EOF with the same live Root and owed posts.
    ///
    /// # Errors
    /// Refuses changed native state, expired original D, an incomplete physical
    /// cleanup or Source transition, and any actual stream or independent post.
    #[doc(hidden)]
    pub fn finish_retained_delete_root_once_v4(
        &self,
        pending: &mut crate::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut ControllerDeletePendingRootClientOriginalV2<'_>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
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
            .finish_source_completion_root_once_v4(
                &mut client.inner,
                controller,
                launch,
                profile.lower_original_v1(),
            )
            .map_err(Into::into)
    }

    /// Prepares final Source/C17 disposition and retires the completed Root owner.
    ///
    /// On refusal the error returns the entire unchanged Root client so the
    /// caller can retain the failed prefix beside the still-held pending owner.
    ///
    /// # Errors
    /// Refuses an incomplete exchange, Source/native/clock posts, changed
    /// current state or unavailable original financial disposition.
    #[doc(hidden)]
    pub fn prepare_retained_delete_final_disposal_v4<'disposal, 'root>(
        &self,
        pending: &'disposal mut crate::ControllerDeletePendingOriginalV2<'_, '_>,
        mut client: ControllerDeletePendingRootClientOriginalV2<'root>,
        controller: &'disposal Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<
        ControllerDeleteFinalDisposalOriginalV4<'disposal>,
        (
            ControllerDeletePendingRootClientOriginalV2<'root>,
            ResourceReservationErrorV1,
        ),
    > {
        if client.inner.require_profile_v2(profile).is_err() {
            return Err((client, ResourceReservationErrorV1::Conflict));
        }
        let Some(launch) = self.launch.as_ref() else {
            return Err((client, ResourceReservationErrorV1::EnrollmentUnavailable));
        };
        let token = match pending.prepare_terminal_positive_disposal_v4(
            &client.inner,
            controller,
            launch,
            profile.lower_original_v1(),
        ) {
            Ok(token) => token,
            Err(cause) => return Err((client, cause.into())),
        };
        client.inner.complete_terminal_upper_disposal_v4();
        drop(client);
        Ok(ControllerDeleteFinalDisposalOriginalV4 { native: token })
    }

    /// Appends the original cleanup anchor after genuine9/62/7 native completion.
    ///
    /// The return value is comparison DATA for the same Root flight. It does
    /// not settle D or release the continuously held Source/C17 original.
    ///
    /// # Errors
    /// Refuses incomplete or foreign receipts, native/financial uncertainty,
    /// changed Root/C/Source, expired original D or any entered-post failure.
    #[doc(hidden)]
    pub fn complete_retained_delete_source_cleanup_once_v4(
        &self,
        pending: &mut crate::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut ControllerDeletePendingRootClientOriginalV2<'_>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        mount: (&[u8; 64], &AuthenticatedBrokerMethodOutcomeV1),
        storage: (&[u8; 64], &AuthenticatedBrokerMethodOutcomeV1),
    ) -> Result<DeleteRootSourceCompletionDataV4, ResourceReservationErrorV1> {
        client
            .inner
            .require_profile_v2(profile)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        pending
            .complete_source_cleanup_once_v4(
                &mut client.inner,
                controller,
                launch,
                profile.lower_original_v1(),
                mount,
                storage,
            )
            .map_err(Into::into)
    }
}
