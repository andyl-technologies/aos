//! Checked semantic slots for authenticated native callback birth records.
//!
//! These helpers check coordinates only. Their callers must separately verify
//! the original native receipt, installed mapper profile, and owner custody.

use crucible_node_contract::{Phase, Position, U64};

use crate::node_contract::OperationFailure;

use super::refusal;

/// Separates every ordered native reaction from its prepared publication slot.
pub(super) fn callback_positions(
    tick: U64,
    tick_ordinal: U64,
    maximum_microsteps: U64,
) -> Result<(Position, Position), OperationFailure> {
    let reaction = tick_ordinal
        .get()
        .checked_sub(1)
        .and_then(|ordinal| ordinal.checked_mul(2))
        .ok_or_else(|| refusal("gem5 native callback tie cannot map to a semantic slot"))?;
    let publication = reaction
        .checked_add(1)
        .filter(|microstep| *microstep < maximum_microsteps.get())
        .ok_or_else(|| refusal("gem5 native callback exceeds admitted same-time closure credit"))?;

    Ok((
        Position::new(tick, U64::new(reaction), Phase::Reaction),
        Position::new(tick, U64::new(publication), Phase::Publication),
    ))
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These positions tests deliberately panic on invalid fixtures or failed invariants.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn callback_ties_preserve_order_and_distinct_publication_slots() {
        let (first, publication) = callback_positions(10.into(), 1.into(), 8.into()).unwrap();
        let (second, _) = callback_positions(10.into(), 2.into(), 8.into()).unwrap();

        assert_eq!(first, Position::new(10.into(), 0.into(), Phase::Reaction));
        assert_eq!(
            publication,
            Position::new(10.into(), 1.into(), Phase::Publication)
        );
        assert_eq!(second, Position::new(10.into(), 2.into(), Phase::Reaction));
        assert!(first < publication && publication < second);
    }

    #[test]
    fn closure_credit_is_checked_before_dispatching_a_callback() {
        assert!(callback_positions(10.into(), 0.into(), 8.into()).is_err());
        assert!(callback_positions(10.into(), 1.into(), 1.into()).is_err());
        assert!(callback_positions(10.into(), 2.into(), 3.into()).is_err());
        assert!(callback_positions(10.into(), 2.into(), 4.into()).is_ok());
    }

    #[test]
    fn native_tie_exhaustion_does_not_wrap_into_an_earlier_position() {
        assert!(callback_positions(10.into(), u64::MAX.into(), u64::MAX.into()).is_err());
    }
}
