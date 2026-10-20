//! Opens distinct Mount62 through the saved Bank's same retained Delete client.

use super::*;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::DeleteRootResourcePurposeDataV3;

impl ControllerResourceBankOpeningV1 {
    /// Borrows Mount's exact request ceiling from its actual completed Root exchange.
    #[doc(hidden)]
    #[must_use]
    pub fn retained_delete_mount_request_bound_v4(
        &self,
        client: &ControllerDeletePendingRootClientOriginalV2<'_>,
    ) -> Option<usize> {
        client.inner.mount_request_bound_v4()
    }

    /// Lends the actual signed62 with its same accepted Source, C and Root owners.
    ///
    /// # Errors
    /// Refuses incomplete9/Host3, another profile/Bank, changed Mount16 native
    /// cut, prior entry or the actual same-account receiving/currentness failure.
    #[doc(hidden)]
    pub fn borrow_retained_delete_mount_reap_once_v4<'held, 'source, 'original, 'root>(
        &'held self,
        pending: &'held mut crate::ControllerDeletePendingOriginalV2<'source, 'original>,
        client: &'held mut ControllerDeletePendingRootClientOriginalV2<'root>,
        controller: &'held mut Journal,
        profile: &'held crate::normal_root::ProductionControllerNormalRootProfileV1,
        inventory: aos_sandbox_protocol::domain_ledger::delete_root::inventory_cuts::DeleteSessionInventoryCutDataV2<'_>,
        shape: crate::StorageProvisioningSessionIoShapeDataV1,
    ) -> Result<crate::OriginalDeleteMountReapLoanV4<'held>, ResourceReservationErrorV1> {
        client.inner.require_profile_v2(profile).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        pending.borrow_mount_reap_once_v4(&mut client.inner, controller, launch,
            profile.lower_original_v1(), inventory, shape).map_err(Into::into)
    }

    /// Exchanges the Mount draft after the actual9 and fresh Host receipt send.
    ///
    /// # Errors
    /// Retains incomplete receipt/native custody, changed same Pending/C/Root,
    /// malformed Host scope, financial refusal or any independent post failure.
    #[doc(hidden)]
    pub fn exchange_retained_delete_mount_resource_draft_once_v4(
        &self,
        pending: &mut crate::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut ControllerDeletePendingRootClientOriginalV2<'_>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
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
        let cut = pending.borrow_completed_preparation_cut_v3(controller)?;
        let (mut fence, accepted, _preparation) = cut.into_parts_v3();
        client
            .inner
            .begin_mount_resource_exchange_once_v4(&mut fence, controller, launch, accepted, host)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        client
            .inner
            .exchange_apply_resource_draft_once_v3(&mut fence, controller, launch, accepted)
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    /// Enters Mount signing through the same concrete signer and accepted loan.
    ///
    /// # Errors
    /// Refuses another purpose, changed native custody or actual same-C funding.
    #[doc(hidden)]
    pub fn begin_retained_delete_mount_resource_signing_once_v4<
        'loan,
        'journal,
        'original,
        'profile,
    >(
        &'loan self,
        pending: &'loan mut crate::ControllerDeletePendingOriginalV2<'journal, 'original>,
        client: &'loan mut ControllerDeletePendingRootClientOriginalV2<'profile>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        authority: &aos_sandbox_protocol::authorization_artifact::SigningAuthority,
        verifier: &aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier,
    ) -> Result<
        OriginalDeleteResourceSigningV2<'loan, 'journal, 'original, 'journal, 'profile>,
        ResourceReservationErrorV1,
    > {
        client
            .inner
            .require_resource_purpose_v4(DeleteRootResourcePurposeDataV3::MountReap62)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.begin_retained_delete_cleanup_signing_inner_v4(
            pending, client, controller, profile, authority, verifier,
        )
    }

    /// Reads Mount's distinct strict approval while all cleanup originals stay held.
    ///
    /// # Errors
    /// Retains wrong purpose, changed receipt/plan/statement or native post failure.
    #[doc(hidden)]
    pub fn receive_retained_delete_mount_approval_once_v4(
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
        client
            .inner
            .require_resource_purpose_v4(DeleteRootResourcePurposeDataV3::MountReap62)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let cut = pending.borrow_completed_preparation_cut_v3(controller)?;
        let (mut fence, accepted, _preparation) = cut.into_parts_v3();
        client
            .inner
            .receive_apply_approval_once_v3(&mut fence, controller, launch, accepted)
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}
