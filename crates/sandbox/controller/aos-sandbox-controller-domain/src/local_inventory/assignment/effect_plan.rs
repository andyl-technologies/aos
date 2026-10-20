//! Derives the private native assignment effect plan from its immutable intent.
//!
//! Fleet observation reduction belongs to the optional Coordinator. This local
//! plan still grants no authority: protected persistence and fresh carrier
//! verification remain independently required at native commit and handoff.

use sha2::{Digest as _, Sha256};

use aos_sandbox_model::state::{DesiredSandboxState, SuspensionMode};
use aos_sandbox_model::{ObjectDigest, OperationId};

use aos_sandbox_model::{AssignmentIntentV1, InvalidAssignmentModel};

/// Carries one exact assignment effect selected by its typed intent reducer.
///
/// The move-only plan retains the complete intent. Its effect commitment is
/// derived internally from that intent and the idempotent operation identity;
/// callers cannot provide an independent digest to be echoed into durability.
#[must_use]
pub(in crate::local_inventory) struct AssignmentEffectPlanV1 {
    operation: OperationId,
    intent: AssignmentIntentV1,
    effect_digest: ObjectDigest,
}

impl AssignmentEffectPlanV1 {
    pub(in crate::local_inventory) fn for_intent(
        operation: OperationId,
        intent: AssignmentIntentV1,
    ) -> Result<Self, InvalidAssignmentModel> {
        if operation.as_bytes() == &[0; 16] {
            return Err(InvalidAssignmentModel::Unspecified);
        }
        let effect_digest = assignment_effect_plan_digest(operation, &intent);
        Ok(Self {
            operation,
            intent,
            effect_digest,
        })
    }

    pub(in crate::local_inventory) const fn operation(&self) -> OperationId {
        self.operation
    }

    pub(in crate::local_inventory) const fn intent(&self) -> &AssignmentIntentV1 {
        &self.intent
    }

    pub(in crate::local_inventory) const fn effect_digest(&self) -> ObjectDigest {
        self.effect_digest
    }

    pub(in crate::local_inventory) fn matches(
        &self,
        operation: OperationId,
        intent: &AssignmentIntentV1,
        effect_digest: ObjectDigest,
    ) -> bool {
        self.operation == operation
            && &self.intent == intent
            && self.effect_digest == effect_digest
            && self.effect_digest == assignment_effect_plan_digest(self.operation, &self.intent)
    }
}

fn assignment_effect_plan_digest(
    operation: OperationId,
    intent: &AssignmentIntentV1,
) -> ObjectDigest {
    let selected = intent.selected_capability_binding();
    let lifecycle = match intent.desired_lifecycle() {
        DesiredSandboxState::Running => [0, 0],
        DesiredSandboxState::Suspended(SuspensionMode::MemoryResident) => [1, 0],
        DesiredSandboxState::Suspended(SuspensionMode::Hibernate) => [1, 1],
        DesiredSandboxState::Stopped => [2, 0],
        DesiredSandboxState::Deleted => [3, 0],
    };
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.multi-node.assignment-effect-plan.v1\0");
    digest.update(operation.as_bytes());
    digest.update(intent.sandbox().as_bytes());
    digest.update(intent.incarnation().as_bytes());
    digest.update(intent.node().as_bytes());
    digest.update(intent.epoch().get().to_be_bytes());
    digest.update(intent.desired_generation().get().to_be_bytes());
    digest.update(intent.assignment_digest().as_bytes());
    digest.update(lifecycle);
    digest.update(selected.lineage().boot().as_bytes());
    digest.update(selected.lineage().generation().to_be_bytes());
    digest.update(selected.sequence().get().to_be_bytes());
    digest.update(selected.evidence_binding_digest().as_bytes());
    digest.update(selected.canonical_frame_digest().as_bytes());
    digest.update(selected.canonical_frame_bytes().to_be_bytes());
    digest.update(selected.coordinator_epoch().to_be_bytes());
    digest.update(selected.authenticated_at_unix_seconds().to_be_bytes());
    digest.update(selected.valid_until_unix_seconds().to_be_bytes());
    digest.update(selected.audience_digest().as_bytes());
    digest.update(selected.disclosure_domain_digest().as_bytes());
    digest.update(selected.carrier_binding_digest().as_bytes());
    digest.update(selected.replay_fence().as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}
