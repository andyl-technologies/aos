//! Projects the actual saved Launch into the fixed D pending consumer only.

use super::*;

impl ControllerResourceBankOpeningV1 {
    /// Commits a genuine authorized Delete's canonical Planned Source fence.
    ///
    /// The caller retains its real six originals and exact candidate models.
    /// This consumes the same authorized Source/C17 pair, never caller native
    /// coordinates, capacity or a replacement Source owner. Entered refusal
    /// runs independently owed posts and terminates with all originals held.
    #[doc(hidden)]
    pub fn commit_authorized_delete_pending_once_v2<'scope, 'original>(
        &self,
        authorized: crate::ControllerDeleteSourceAuthorizedScopeV1<'scope, 'original>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        request_scope: crate::ControllerRequestScopeV1,
        operation: crate::lifecycle::LifecycleOperationV1,
        batch: aos_sandbox_protocol::domain_ledger::delete_batch::LifecycleDeleteBatchV1,
    ) -> crate::ControllerDeletePendingOriginalV2<'scope, 'original> {
        let launch = match self.launch.as_ref() {
            Some(launch) => launch,
            None => std::process::abort(),
        };
        authorized.commit_pending_inner_v2(controller, launch, profile.lower_original_v1(),
            request_scope, operation, batch)
    }
}
