//! Pure complete-cut geometry regressions; these issue no native permission.

use super::*;

#[test]
fn queued_condition_delivery_waits_until_its_successor_reaction_fits() {
    let delivery = Position::new(513_010.into(), 1.into(), Phase::Delivery);
    let premature = Position::new(513_010.into(), 2.into(), Phase::BoundaryControl);
    let reaction = Position::new(513_010.into(), 2.into(), Phase::Reaction);
    let complete = Position::new(513_010.into(), 3.into(), Phase::BoundaryControl);

    assert!(matches!(
        condition_input_fits(delivery, premature),
        Ok(false)
    ));
    assert!(matches!(
        condition_input_fits(delivery, reaction),
        Ok(false)
    ));
    assert!(matches!(condition_input_fits(delivery, complete), Ok(true)));
}

#[test]
fn future_condition_input_does_not_block_an_earlier_empty_cut() {
    let delivery = Position::new(513_010.into(), 1.into(), Phase::Delivery);
    let earlier = Position::new(513_010.into(), 1.into(), Phase::BoundaryControl);

    assert!(matches!(condition_input_fits(delivery, earlier), Ok(true)));
}

#[test]
fn exhausted_condition_microstep_never_wraps_into_an_earlier_reaction() {
    let delivery = Position::new(513_010.into(), u64::MAX.into(), Phase::Delivery);
    let cutoff = Position::new(513_011.into(), 0.into(), Phase::BoundaryControl);

    assert!(condition_input_fits(delivery, cutoff).is_err());
}

#[test]
fn retention_budget_is_bounded_before_any_native_world_exists() -> Result<(), NodeObservedError> {
    assert!(ConditionExecution::new(0).is_err());
    assert!(ConditionExecution::new(15).is_err());
    assert!(ConditionExecution::new(65_537).is_err());
    let driver = ConditionExecution::new(16)?;
    assert!(driver.publications().is_empty());
    assert!(driver.pending_operation().is_none());
    Ok(())
}
