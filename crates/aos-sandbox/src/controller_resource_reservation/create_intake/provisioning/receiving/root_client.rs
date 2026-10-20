//! Mints the Root client only from this same intrinsic completed Create.

use super::*;
use crate::normal_root::RootStorageApplyClientOriginalV1;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;

impl OriginalCreateProvisioningRootLoanV1<'_, '_> {
    /// Starts one separately paid Root Apply connection from the actual originals.
    ///
    /// The whole reached native attempt is returned even when its IO refuses.
    /// The installed caller retains it before inspecting its failure. No parsed
    /// reply, resource vector or historical receipt can construct this owner.
    ///
    /// # Errors
    /// Refuses reentry, another Ready/outcome, or preconstruction funding. The
    /// same receiver retains its actual refusal and still owes its native after.
    #[doc(hidden)]
    pub fn begin_storage_apply_root_once_v1(&mut self, controller: &Journal,
        ready: &[u8], outcome: &AuthenticatedBrokerMethodOutcomeV1,
        co_resident: ResourceVector,
    ) -> Result<RootStorageApplyClientOriginalV1, ResourceReservationErrorV1> {
        if self.receiving.root_client_entered {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.receiving.root_client_entered = true;
        self.require_storage_apply_inputs_v1(controller, ready, outcome)?;
        RootStorageApplyClientOriginalV1::begin_original_once_v1(self, controller,
            ready, outcome, co_resident)
    }

    pub(crate) fn completed_original_v1(&self)
        -> &crate::controller_resource_reservation::CreateStorageCompletedIntakeOriginalV1<'_>
    {
        &self.completed
    }

    pub(crate) fn retained_profile_v1(&self) -> Arc<ProductionControllerNormalRootProfileV1> {
        Arc::clone(&self.receiving.profile)
    }

    pub(crate) fn native_turn_v1(&self) -> u64 {
        self.receiving.native_turn_v1()
    }

    pub(crate) fn original_receiving_v1(&self) -> &CreateProvisioningOriginalsV1 {
        self.receiving
    }

    pub(crate) fn parent_operation_v1(&self) -> aos_sandbox_core::OperationId {
        self.receiving.parent
    }
}
