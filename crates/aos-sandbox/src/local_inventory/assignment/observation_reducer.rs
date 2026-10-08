//! Optional assignment-observation reduction and semantic-plan selection.
//!
//! This owner retains the complete warm observation fold for the selected remote
//! assignment integration. Intent DATA, protected history, and the private plan
//! factory remain in their original lower owners.

use std::cmp::Ordering;

use aos_sandbox_core::OperationId;

use super::{
    AssignmentEffectPlanV1, AssignmentIntentV1, InvalidAssignmentModel, NodeAssignmentObservationV1,
};

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
