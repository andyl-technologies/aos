//! Local debugger authorization and canonical branch execution on one owner.
//!
//! Imported finding handles reuse this owner's authentic repository, queue and
//! immutable production lifecycle. Neither a branch nor its publication opens
//! another capacity actor or substitutes a raw private storage namespace.

use super::*;
use crate::qemu_campaign_lifecycle::GuardedFindingBranchError;
use crucible_campaign::{
    AttemptId, BranchRequest, BranchRequestResult, DebugSessionId, DebuggerSubmission,
};

impl GuardedCampaignOwner {
    /// Authorizes a local branch with the receiver owner's original debugger key.
    ///
    /// # Errors
    /// Refuses owners without local debugger authority, changed campaign heads,
    /// invalid requests, or authenticated repository transaction failures.
    pub fn authorize_branch_request(
        &self,
        campaign: &CampaignName,
        session: DebugSessionId,
        request: BranchRequest,
    ) -> Result<BranchRequestResult, GuardedFindingBranchError> {
        let key = self
            .inner
            .debugger
            .as_ref()
            .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)?;
        let head = self.inner.repository.head(campaign.as_str())?;
        let submission = DebuggerSubmission::authorize(key, head.snapshot_id(), session, request)?;
        Ok(self
            .inner
            .repository
            .submit_debugger_branch_request(campaign.as_str(), &submission)?)
    }

    /// Executes an already admitted canonical attempt on the same charged actor.
    ///
    /// The owner's immutable lifecycle and host contract remain authoritative.
    /// The caller supplies its original boundary and cancellation handle; this
    /// method neither opens a new executor nor resets an operation deadline.
    ///
    /// # Errors
    /// Refuses incompatible lineage, resource exhaustion, canceled original
    /// supervision, native execution failure, and missing canonical completion.
    pub fn run_admitted_branch(
        &self,
        campaign: &CampaignName,
        target: AttemptId,
        cancellation: ExecutionCancellation,
        caller_supervisor: &crucible_linux_resource::host_supervision::HostOperationSupervisor,
        boundary: &mut dyn FnMut() -> std::io::Result<()>,
    ) -> Result<crucible_campaign::Observation, GuardedFindingBranchError> {
        crate::qemu_campaign_lifecycle::run_admitted_finding_branch(
            self,
            campaign,
            target,
            cancellation,
            caller_supervisor,
            boundary,
        )
    }
}
