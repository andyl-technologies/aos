//! Lends the Bank's saved Launch only to the genuine C17 Cache query.
//!
//! The actual initialized Cache owners and authorized Source scope remain
//! borrowed by the returned query. No Launch, writer or financial getter is
//! exposed, and no Create/Boot loan or historical inventory is substituted.

use super::*;
use crate::cache_programmes::{CacheDeleteInventoryQueryV1, CacheResidentInitializationV1};
use aos_sandbox_cache::{CacheResidencyProtectedOwnerV1, DormantCacheOwnerV1};
use crate::normal_root::ProductionControllerNormalRootProfileV1;

impl ControllerResourceBankOpeningV1 {
    /// Borrows the five actual Cache originals under the same authorized C17.
    ///
    /// # Errors
    /// Refuses missing saved Launch, foreign initialized Cache originals,
    /// incomplete genuine initialization/Root6 continuation, or C17 admission failure.
    #[doc(hidden)]
    pub fn borrow_delete_planning_cache_once_v1<'query, 'cache, 'scope, 'original, 'profile>(
        &'query self,
        initialized: &'cache mut CacheResidentInitializationV1,
        cache: &'cache mut CacheResidencyProtectedOwnerV1,
        physical: &'cache DormantCacheOwnerV1,
        authorized: &'query mut crate::ControllerDeleteSourceAuthorizedScopeV1<'scope, 'original>,
        controller: &'query mut Journal,
        profile: &'profile ProductionControllerNormalRootProfileV1,
    ) -> Result<CacheDeleteInventoryQueryV1<'query, 'cache, 'query, 'scope, 'original, 'scope, 'profile>, ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        initialized.begin_delete_planning_query_v1(cache, physical, authorized,
            controller, launch, profile.lower_original_v1()).map_err(Into::into)
    }

    /// Moves the same completed planning Cache originals into a pending query.
    ///
    /// The real initial owner remains in `retained` on every pre-entry refusal.
    /// The fresh query retains its completed predecessor payloads and uses the
    /// same five-reader/native/metadata engine without reopening any journal.
    ///
    /// # Errors
    /// Refuses missing/uncertain planning custody, a foreign or expired actual
    /// Root/Pending association, changed Launch/profile or the same C17 bound.
    /// Every retained refusal remains on the original Cache or Pending owner.
    #[doc(hidden)]
    pub fn begin_retained_delete_pending_cache_once_v2<'query, 'cache, 'journal, 'original, 'profile>(
        &'query self,
        retained: &mut Option<crate::cache_programmes::CacheDeleteInventoryOriginalV1<'cache>>,
        pending: &'query mut crate::ControllerDeletePendingOriginalV2<'journal, 'original>,
        controller: &'query mut Journal,
        profile: &'profile ProductionControllerNormalRootProfileV1,
        challenge: &'query super::ControllerDeletePendingRootChallengeLoanV2<'query>,
    ) -> Result<CacheDeleteInventoryQueryV1<'query, 'cache, 'query, 'journal, 'original, 'journal, 'profile>, ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let fence = pending.borrow_fence_v2()?;
        let original = retained.take().ok_or(ResourceReservationErrorV1::Conflict)?;
        match original.into_pending_query_once_v2(fence, controller, launch,
            profile.lower_original_v1(), challenge.actual_challenge_v2())
        {
            Ok(query) => Ok(query),
            Err(original) => {
                *retained = Some(original);
                Err(ResourceReservationErrorV1::Conflict)
            }
        }
    }
}
