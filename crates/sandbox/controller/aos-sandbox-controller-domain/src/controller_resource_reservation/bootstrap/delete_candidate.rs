//! Keeps the candidate's actual Source/C17 and saved Launch joins private.

use super::*;
use aos_sandbox_model::ResourceVector;
use crate::cache_programmes::CacheDeleteInventoryOriginalV1;
use crate::public_mutation_compiler::delete_admission::{
    ControllerDeleteCandidateOriginalV2, ControllerDeleteSourceAuthorizedScopeV1,
};
use crate::normal_root::ProductionControllerNormalRootProfileV1;

impl ControllerResourceBankOpeningV1 {
    pub(crate) fn require_delete_candidate_cache_v2(
        &self,
        cache: &CacheDeleteInventoryOriginalV1<'_>,
        authorized: &ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        cache.require_planning_binding_v1(authorized, controller, launch, profile.lower_original_v1())
            .map_err(Into::into)
    }

    pub(crate) fn reserve_delete_candidate_v2(
        &self,
        authorized: &mut ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        additional: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        authorized.reserve_planning_root_additional_v1(
            controller, launch, profile.lower_original_v1(), additional,
        ).map_err(Into::into)
    }

    pub(crate) fn delete_candidate_boundaries_v2(
        &self,
        authorized: &ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(u64, u64), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        authorized.planning_root_cut_data_v1(controller, launch, profile.lower_original_v1())
            .map(|cut| (cut.controller_next, cut.source_next))
            .map_err(Into::into)
    }

    /// Produces candidate DATA from this exact authorized Source and Cache cut.
    ///
    /// The six descriptors remain DATA here. The actual Collection borrower
    /// must compare all six originals again before it can commit Planned and
    /// enter Root's independent initial-prefix verification.
    ///
    /// # Errors
    /// Refuses a foreign/incomplete Cache cut or fixed admission before native
    /// identity entry. Entered refusals remain on the returned whole owner.
    #[doc(hidden)]
    pub fn prepare_authorized_delete_candidate_once_v2(
        &self,
        authorized: &mut ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        cache: &CacheDeleteInventoryOriginalV1<'_>,
        request_scope: crate::ControllerRequestScopeV1,
        owners: [aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchOwnerCutDataV2; 6],
        initial_six: [u8; 32],
    ) -> Result<ControllerDeleteCandidateOriginalV2, ResourceReservationErrorV1> {
        authorized.prepare_candidate_once_v2(
            self, controller, profile, cache, request_scope, owners, initial_six,
        )
    }
}
