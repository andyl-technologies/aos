//! Parks the same authenticated Agent completion until actual monitor posts.
//!
//! This mechanical destination carries no execution permission. The normal
//! sender immediately invokes the same final commit recipe. An ongoing monitor
//! retains the signed packet and typed completion while its independently owed
//! native observations run; only its sealed positive post owner can finalize.

use aos_sandbox_model::runtime_backend::BackendExecutionInspectionV1;
use aos_sandbox_controller_domain::runtime_execution::JournalExecutionCompletionV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use super::*;

pub(super) struct AgentCompletionWorkV5 {
    pub(super) issued: DurableExecutionEffectV1,
    pub(super) packet: aos_sandbox_guest_protocol::SignedAgentOutcomePacketV1,
    pub(super) observation: BackendExecutionInspectionV1,
    pub(super) completion: JournalExecutionCompletionV1,
    pub(super) next_sequence: AgentOperationSequenceV1,
}

pub(crate) struct AgentDeferredCompletionOriginalV5 {
    entered: bool,
    work: Option<AgentCompletionWorkV5>,
    finish: Option<Result<DurableExecutionEffectV1, HostAgentLiveErrorV1>>,
}

impl AgentDeferredCompletionOriginalV5 {
    pub(crate) fn new() -> Self {
        Self { entered: false, work: None, finish: None }
    }

    // Native send/receive owners have their own exact supplier. These are only
    // the additional parked canonical spec/result planes and carrier overlap.
    pub(crate) fn receiving_demand_v5(specification_bytes: usize) -> Option<ResourceVector> {
        if specification_bytes > MAX_AGENT_SEALED_SPEC_BYTES_V1 { return None; }
        let bytes = specification_bytes.checked_mul(3)?
            .checked_add(aos_sandbox_guest_protocol::signed_outcome_packet::observe_signed_outcome_packet_bytes_v5()?.checked_mul(4)?)?
            .checked_add(aos_sandbox_protocol::execution_evidence::execution_completion_evidence_bytes_v5()
                .checked_mul(6)?)?
            .checked_add(2 * std::mem::size_of::<AgentCompletionWorkV5>())?
            .checked_add(2 * std::mem::size_of::<Self>())?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
    }

    pub(super) fn park_once_v5(&mut self, work: AgentCompletionWorkV5)
        -> Result<(), HostAgentLiveErrorV1>
    {
        if !self.entered || self.work.is_some() || self.finish.is_some() {
            return Err(HostAgentLiveErrorV1::RecoveryRequired);
        }
        self.work = Some(work);
        Ok(())
    }

    pub(crate) fn failure_v5(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.finish.as_ref()?.as_ref().err().map(|cause| cause as _)
    }

    pub(crate) fn completed_v5(&self) -> Option<&DurableExecutionEffectV1> {
        self.finish.as_ref()?.as_ref().ok()
    }
}

impl HostAgentLiveSessionV1 {
    pub(crate) fn issue_pending_monitor_effect_v5(
        &mut self,
        claim: &mut DormantRuntimeExecutionClaimV1<'_>,
        pending: &DurableExecutionEffectV1,
        deadline: Instant,
        cutoff: u64,
        original: &mut execution_original::AgentExecutionOriginalV2,
        deferred: &mut AgentDeferredCompletionOriginalV5,
        before_native_write: &mut dyn FnMut() -> Result<(), HostAgentLiveErrorV1>,
    ) -> Result<DurableExecutionEffectV1, HostAgentLiveErrorV1> {
        if pending.issue().operation() != EffectOperationV1::Observe
            || original.entered || deferred.entered || deferred.work.is_some()
        {
            return Err(HostAgentLiveErrorV1::RecoveryRequired);
        }
        original.entered = true;
        deferred.entered = true;
        self.issue_pending_effect_engine_v2(claim, pending, deadline, cutoff,
            Some(original), None, Some(before_native_write), Some(deferred))
    }

    pub(crate) fn finish_deferred_monitor_completion_v5(
        &mut self,
        claim: &mut DormantRuntimeExecutionClaimV1<'_>,
        original: &mut AgentDeferredCompletionOriginalV5,
        posts: &crate::broker::ExecutionMonitorPostsPositiveV5<'_>,
    ) -> Result<DurableExecutionEffectV1, HostAgentLiveErrorV1> {
        if !self.poisoned || !original.entered || original.finish.is_some() {
            return Err(HostAgentLiveErrorV1::RecoveryRequired);
        }
        let work = original.work.as_ref().ok_or(HostAgentLiveErrorV1::RecoveryRequired)?;
        // This typed owner borrows the actual completed native pair, name
        // observations and ongoing clock. A supplied success scalar cannot
        // expose a Complete row ahead of any independently owed post.
        original.finish = Some((|| {
            posts.require_pending_v5(&work.issued)?;
            self.validate_claim(claim)?;
            self.commit_completion_work_v5(claim, work)
        })());
        original.finish.as_ref().and_then(|result| result.as_ref().ok()).cloned()
            .ok_or(HostAgentLiveErrorV1::RecoveryRequired)
    }
}
