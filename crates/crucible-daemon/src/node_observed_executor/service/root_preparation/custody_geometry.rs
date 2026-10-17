//! Bounds custody capsules separately from admitted Root worker worlds.
//!
//! Each dedicated worker admits one original world. Initial preparation owns one
//! runtime capsule; restoration simultaneously retains an independent staging
//! capsule and runtime capsule. These slots do not admit another public world.

use super::{NodeObservationServiceError, RootPreparationAction, refused};

const MAXIMUM_ADMITTED_WORLDS: usize = 64;
const RESTORE_CAPSULES: usize = 2;

/// Checks the dedicated Root workers' worst-case inventory before catalog creation.
pub(super) fn slots(
    action: &RootPreparationAction,
    maximum_admitted_worlds: usize,
) -> Result<usize, NodeObservationServiceError> {
    let aggregate = maximum_admitted_worlds
        .checked_mul(RESTORE_CAPSULES)
        .ok_or_else(|| refused("Root custody capsule inventory overflows"))?;
    if maximum_admitted_worlds == 0
        || maximum_admitted_worlds > MAXIMUM_ADMITTED_WORLDS
        || aggregate > crucible_node_contract::MAX_ARRAY_ELEMENTS
    {
        return Err(refused(
            "Root aggregate custody capsule inventory exceeds finite credit",
        ));
    }

    // The actor's original worker/retired-world admission quota remains the
    // admission fence. The catalog parameter provisions cleanup obligations.
    Ok(match action {
        RootPreparationAction::ContinueHeldUart { .. } => RESTORE_CAPSULES,
        RootPreparationAction::DescribeHeldUart {} | RootPreparationAction::CaptureHeldUart {} => 1,
    })
}

#[cfg(test)]
#[path = "custody_geometry_tests.rs"]
mod tests;
