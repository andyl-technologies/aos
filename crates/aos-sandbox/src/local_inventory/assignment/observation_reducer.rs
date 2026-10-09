//! Optional assignment-observation reduction and semantic-plan selection.
//!
//! This owner retains the complete warm observation fold and private move-only
//! plan factory for the selected remote assignment integration. Intent DATA and
//! protected history remain in their original lower owners; a selected plan
//! still requires protected commit and independent effect-time verification.

use std::cmp::Ordering;

use sha2::{Digest as _, Sha256};

use aos_sandbox_core::state::{DesiredSandboxState, SuspensionMode};
use aos_sandbox_core::{ObjectDigest, OperationId};

use super::{AssignmentIntentV1, InvalidAssignmentModel, NodeAssignmentObservationV1};

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
    fn from_reducer(operation: OperationId, intent: AssignmentIntentV1) -> Option<Self> {
        if operation.as_bytes() == &[0; 16] {
            return None;
        }
        let effect_digest = assignment_effect_plan_digest(operation, &intent);
        Some(Self {
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

/// Reports the result of reducing one assignment observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssignmentObservationApplyOutcomeV1 {
    /// Reducer state changed.
    Applied,
    /// The exact current observation was replayed.
    Replay,
    /// An older observation from the current boot was ignored.
    Stale,
    /// A valid observation from a prior node boot was ignored.
    PriorBoot,
}

/// Reduces observations for one fixed canonical assignment intent.
///
/// This reducer validates identity, order, and phase transitions only. Even an
/// `Active` result is an observation requiring independent ownership and
/// guardian validation before the controller may issue effects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssignmentObservationReducerV1 {
    intent: AssignmentIntentV1,
    current: Option<NodeAssignmentObservationV1>,
}

impl AssignmentObservationReducerV1 {
    /// Creates an empty observation reducer for exact controller intent.
    #[must_use]
    pub fn new(intent: AssignmentIntentV1) -> Self {
        Self {
            intent,
            current: None,
        }
    }

    /// Returns the immutable assignment intent.
    #[must_use]
    pub const fn intent(&self) -> &AssignmentIntentV1 {
        &self.intent
    }

    /// Issues a typed semantic plan for this reducer's exact immutable intent.
    ///
    /// The plan grants no carrier or effect authority by itself. Protected-store
    /// commit and effect-time carrier verification remain independently required.
    pub(in crate::local_inventory) fn issue_effect_plan(
        &self,
        operation: OperationId,
    ) -> Result<AssignmentEffectPlanV1, InvalidAssignmentModel> {
        AssignmentEffectPlanV1::from_reducer(operation, self.intent.clone())
            .ok_or(InvalidAssignmentModel::Unspecified)
    }

    /// Returns the latest observation while its carrier and authority evidence is current.
    #[must_use]
    pub fn current_at(
        &self,
        coordinator_unix_seconds: u64,
    ) -> Option<&NodeAssignmentObservationV1> {
        self.current.as_ref().filter(|observation| {
            observation
                .context()
                .is_current_at(coordinator_unix_seconds)
                && observation.observed_at_unix_seconds() <= coordinator_unix_seconds
                && observation
                    .authority()
                    .is_none_or(|authority| authority.is_current_at(coordinator_unix_seconds))
        })
    }

    /// Reduces one already authenticated node observation.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAssignmentModel`] for expired evidence, tuple mismatch,
    /// future desired generation, same-sequence equivocation, or an impossible
    /// phase transition.
    pub fn apply(
        &mut self,
        observation: NodeAssignmentObservationV1,
        coordinator_unix_seconds: u64,
    ) -> Result<AssignmentObservationApplyOutcomeV1, InvalidAssignmentModel> {
        if !observation
            .context()
            .is_current_at(coordinator_unix_seconds)
            || observation.observed_at_unix_seconds() > coordinator_unix_seconds
            || observation
                .authority()
                .is_some_and(|authority| !authority.is_current_at(coordinator_unix_seconds))
        {
            return Err(InvalidAssignmentModel::AuthorityMismatch);
        }
        if observation.desired_generation() > self.intent.desired_generation() {
            return Err(InvalidAssignmentModel::DesiredGenerationAhead);
        }
        if !observation.matches(&self.intent) {
            return Err(InvalidAssignmentModel::AssignmentMismatch);
        }

        let placement_lineage = self.intent.selected_capability_lineage();
        if observation.boot_generation() < self.intent.selected_capability_boot_generation() {
            return Ok(AssignmentObservationApplyOutcomeV1::PriorBoot);
        }
        match observation
            .boot_generation()
            .cmp(&placement_lineage.generation())
        {
            Ordering::Equal if observation.lineage() != placement_lineage => {
                return Err(InvalidAssignmentModel::BootConflict);
            }
            Ordering::Greater
                if !observation
                    .lineage()
                    .is_direct_successor_of(placement_lineage) =>
            {
                return Err(InvalidAssignmentModel::BootLineageGap);
            }
            _ => {}
        }

        let Some(current) = &self.current else {
            self.current = Some(observation);
            return Ok(AssignmentObservationApplyOutcomeV1::Applied);
        };

        if observation.boot_generation() < current.boot_generation() {
            return Ok(AssignmentObservationApplyOutcomeV1::PriorBoot);
        }
        if observation.boot_generation() > current.boot_generation() {
            if !observation
                .lineage()
                .is_direct_successor_of(current.lineage())
            {
                return Err(InvalidAssignmentModel::BootLineageGap);
            }
            self.current = Some(observation);
            return Ok(AssignmentObservationApplyOutcomeV1::Applied);
        }
        if observation.lineage() != current.lineage() {
            return Err(InvalidAssignmentModel::BootConflict);
        }

        match observation.sequence().cmp(&current.sequence()) {
            Ordering::Less => Ok(AssignmentObservationApplyOutcomeV1::Stale),
            Ordering::Equal if observation == *current => {
                Ok(AssignmentObservationApplyOutcomeV1::Replay)
            }
            Ordering::Equal => Err(InvalidAssignmentModel::SequenceConflict),
            Ordering::Greater => {
                if !current.phase().can_transition_to(observation.phase()) {
                    return Err(InvalidAssignmentModel::InvalidPhaseTransition);
                }
                self.current = Some(observation);
                Ok(AssignmentObservationApplyOutcomeV1::Applied)
            }
        }
    }
}
