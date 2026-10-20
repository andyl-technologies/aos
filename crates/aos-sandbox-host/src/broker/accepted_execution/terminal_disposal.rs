//! Retains actual signed Guest terminal provenance until physical Stage drop.
//!
//! This is private ownership-phase evidence, never a read, Stop or execution
//! permission. The actual native claim supplies the sole constructor; copied
//! phase/status/result DATA cannot create it. Capture additionally requires its
//! real retained Storage Complete and native marker frontier.

use aos_sandbox::runtime_execution::DormantRuntimeExecutionClaimV1;
use aos_sandbox_core::{ExecutionId, ObjectDigest};
use aos_sandbox_core::runtime_backend::DurableExecutionEffectV1;
use crate::execution_effect::HostExecutionEffectErrorV1;

pub(in crate::broker) struct HostGuestTerminalNativeV3 {
    complete: ObjectDigest,
    execution: ExecutionId,
    runtime: ObjectDigest,
}

impl HostGuestTerminalNativeV3 {
    pub(in crate::broker) fn observe_actual_claim_v3(
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        effect: &DurableExecutionEffectV1,
    ) -> Result<Option<Self>, HostExecutionEffectErrorV1> {
        let Some(completion) = effect.completion() else { return Ok(None); };
        let original = crate::execution_effect::terminal_guest_result(claim, effect, completion)?;
        if original.is_empty() { return Ok(None); }
        Ok(Some(Self {
            complete: effect.record_commitment(),
            execution: effect.admission().execution(),
            runtime: effect.admission().currentness().runtime().handle(),
        }))
    }

    pub(in crate::broker) fn matches_actual_complete_v3(&self, effect: &DurableExecutionEffectV1) -> bool {
        self.complete == effect.record_commitment()
            && self.execution == effect.admission().execution()
            && self.runtime == effect.admission().currentness().runtime().handle()
    }
}
