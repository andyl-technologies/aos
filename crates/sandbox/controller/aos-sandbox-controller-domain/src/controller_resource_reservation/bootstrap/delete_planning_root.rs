//! Lends the same Bank's private Launch to authorized Root planning comparison.
//!
//! Actual C17/Source scope, measured production profile and Root client remain
//! the genuine owners. These finite projections expose no raw Launch, account,
//! writer, nonce, supplied amount or comparison-to-authority constructor.

use super::*;

impl ControllerResourceBankOpeningV1 {
    /// Starts the actual planning client through this Bank's saved Launch.
    ///
    /// # Errors
    /// Refuses missing Launch or same-owner/financial admission before entry.
    /// Entered native failures remain on the returned whole client.
    pub(crate) fn begin_delete_planning_root_client_once_v1<'profile>(
        &self,
        scope: &mut crate::public_mutation_compiler::delete_admission::ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        controller: &mut Journal,
        profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<
        crate::normal_root::RootDeletePlanningClientOriginalV1<'profile>,
        ResourceReservationErrorV1,
    > {
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        crate::normal_root::RootDeletePlanningClientOriginalV1::begin_authorized_once_v1(
            scope, controller, launch, profile,
        )
        .map_err(Into::into)
    }

    /// Borrows only the real completed planning client's original observation.
    ///
    /// # Errors
    /// Refuses changed genuine scope/C/predecessor, earlier native uncertainty,
    /// incomplete original posts or expiration of its original five-second cut.
    /// The returned DATA loan cannot construct the Runtime default-off owner,
    /// pending state, six-cut proof or Root accepting floor.
    pub(crate) fn borrow_delete_planning_root_observation_v1<'borrow>(
        &self,
        client: &'borrow mut crate::normal_root::RootDeletePlanningClientOriginalV1<'_>,
        scope: &crate::public_mutation_compiler::delete_admission::ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        controller: &Journal,
    ) -> Result<
        crate::normal_root::RootDeletePlanningObservationLoanV1<'borrow>,
        ResourceReservationErrorV1,
    > {
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        client
            .borrow_observation_v1(scope, controller, launch)
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}

/// Retains the genuine completed Root planning exchange on its original profile.
///
/// This opaque owner is constructed only by the named same-Bank C17 entrance.
/// Its actual native client retains every first error and aborts uncertain
/// abandonment. It provides neither a six-domain grant nor pending authority.
#[doc(hidden)]
#[must_use]
pub struct ControllerDeletePlanningRootOriginalV1<'profile> {
    inner: crate::normal_root::RootDeletePlanningClientOriginalV1<'profile>,
}

/// Borrows canonical comparison DATA from the same completed native exchange.
///
/// No public constructor, decoded bytes or supplied Result can produce this
/// loan. Each borrow rechecks the actual authorized Source/C17/C predecessor
/// and the original five-second horizon through the sole native client.
#[doc(hidden)]
pub struct ControllerDeletePlanningRootLoanV1<'borrow> {
    inner: crate::normal_root::RootDeletePlanningObservationLoanV1<'borrow>,
}

impl ControllerDeletePlanningRootOriginalV1<'_> {
    /// Borrows the first original native or semantic refusal, if one occurred.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.failure()
    }
}

impl ControllerDeletePlanningRootLoanV1<'_> {
    /// Borrows the authenticated full canonical observation preimage.
    #[must_use]
    pub fn bytes_v2(&self) -> &[u8; aos_sandbox_protocol::domain_ledger::delete_root::planning::DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2] {
        self.inner.bytes_v2()
    }

    /// Borrows the actual original authorized opening and full C/Source cut.
    #[must_use]
    pub fn open_v3(&self) -> &aos_sandbox_protocol::domain_ledger::delete_root::planning::DeleteRootPlanningOpenDataV3 {
        self.inner.open_v3()
    }

    /// Borrows the real fresh Root challenge clamped to the original horizon.
    #[must_use]
    pub fn challenge_v3(&self) -> &aos_sandbox_protocol::domain_ledger::delete_root::planning::DeleteRootPlanningChallengeDataV3 {
        self.inner.challenge_v3()
    }

    /// Borrows the complete Root namespace and actual Ownership observations.
    #[must_use]
    pub fn observation_v2(&self) -> &aos_sandbox_protocol::domain_ledger::delete_root::planning::DeleteRootPlanningObservationDataV2 {
        self.inner.observation_v2()
    }
}

impl ControllerResourceBankOpeningV1 {
    /// Enters the fixed Root planning exchange on this Bank's saved Launch.
    ///
    /// Only the actual continuously held authorized Source/C17 owner and
    /// measured profile qualify it. Extra wrapper/loan construction is paid
    /// on that same original before the existing client is constructed.
    ///
    /// # Errors
    /// Returns pre-entry funding or same-owner refusals. Any entered native
    /// failure remains on the returned opaque original and its actual client.
    #[doc(hidden)]
    pub fn begin_delete_planning_comparison_once_v1<'profile>(
        &self,
        scope: &mut crate::ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        controller: &mut Journal,
        profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<ControllerDeletePlanningRootOriginalV1<'profile>, ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let bytes = std::mem::size_of::<ControllerDeletePlanningRootOriginalV1<'_>>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ControllerDeletePlanningRootLoanV1<'_>>().checked_mul(3)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        scope.reserve_planning_root_additional_v1(controller, launch,
            profile.lower_original_v1(), aos_sandbox_model::ResourceVector::ZERO.with(
                aos_sandbox_model::ResourceDimension::MemoryBytes, bytes))?;
        let inner = self.begin_delete_planning_root_client_once_v1(scope, controller, profile)?;
        Ok(ControllerDeletePlanningRootOriginalV1 { inner })
    }

    /// Lends only this actual completed planning comparison on the same owner.
    ///
    /// # Errors
    /// Refuses foreign/changed authorization, C/Source/profile/Launch, earlier
    /// uncertainty or expiry. The loan cannot complete the Runtime Ownership
    /// configuration join, construct six cuts, or admit a pending mutation.
    #[doc(hidden)]
    pub fn borrow_delete_planning_comparison_v1<'borrow>(
        &self,
        original: &'borrow mut ControllerDeletePlanningRootOriginalV1<'_>,
        scope: &crate::ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        controller: &Journal,
    ) -> Result<ControllerDeletePlanningRootLoanV1<'borrow>, ResourceReservationErrorV1> {
        let inner = self.borrow_delete_planning_root_observation_v1(
            &mut original.inner, scope, controller)?;
        Ok(ControllerDeletePlanningRootLoanV1 { inner })
    }
}

impl ControllerResourceBankOpeningV1 {
    /// Runs the already owed joint Source/C17 post while failed Root stays held.
    ///
    /// This purpose-closed negative route borrows the same original Source and
    /// the Bank's saved Launch; it performs no admission or healthy reentry.
    ///
    /// # Errors
    /// Retains native Source/C post failure or refuses missing/repeated state.
    #[doc(hidden)]
    pub fn finish_delete_planning_source_failure_once_v1(&self,
        scope: &mut crate::ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        scope.finish_outer_source_failure_once_v1(controller, launch, profile.lower_original_v1())
            .map_err(Into::into)
    }
}
