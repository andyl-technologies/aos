//! Public API tests for deterministic guest-visible clock skew.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    ClockDriftRate, NodeClockSkew, ScenarioDef, SimOffset, TimeConversionError, VirtualInstant,
};

#[test]
fn clock_skew_distorts_guest_visible_time_without_moving_scheduler_time() {
    let scheduler_time = VirtualInstant { nanos: 12 };
    let skew = NodeClockSkew {
        offset: SimOffset { nanos: 4 },
        drift_rate: drift_rate(5, 2),
    };

    assert_eq!(
        skew.guest_visible_time(scheduler_time),
        Ok(VirtualInstant { nanos: 34 })
    );
    assert_eq!(scheduler_time, VirtualInstant { nanos: 12 });
    assert_eq!(
        NodeClockSkew::PERFECT.guest_visible_time(scheduler_time),
        Ok(scheduler_time)
    );
}

#[test]
fn clock_skew_uses_integer_floor_rounding_and_epoch_saturation() {
    let skew = NodeClockSkew {
        offset: SimOffset { nanos: 0 },
        drift_rate: drift_rate(2, 3),
    };
    let negative = NodeClockSkew {
        offset: SimOffset { nanos: -100 },
        drift_rate: ClockDriftRate::ONE,
    };

    assert_eq!(
        skew.guest_visible_time(VirtualInstant { nanos: 10 }),
        Ok(VirtualInstant { nanos: 6 })
    );
    assert_eq!(
        negative.guest_visible_time(VirtualInstant { nanos: 50 }),
        Ok(VirtualInstant::EPOCH)
    );
}

#[test]
fn clock_skew_material_keeps_default_byte_identical_to_absence() {
    let base = "scenario=public-clock-skew\nnode=a";
    let skew = NodeClockSkew {
        offset: SimOffset { nanos: -25 },
        drift_rate: drift_rate(999, 1000),
    };
    let no_skew = material_with_skew(base, NodeClockSkew::PERFECT);
    let equivalent_no_skew = material_with_skew(
        base,
        NodeClockSkew {
            offset: SimOffset { nanos: 0 },
            drift_rate: drift_rate(2, 2),
        },
    );
    let with_skew = material_with_skew(base, skew);

    assert_eq!(NodeClockSkew::default(), NodeClockSkew::PERFECT);
    assert_eq!(no_skew, base);
    assert_eq!(equivalent_no_skew, base);
    assert!(with_skew.contains("clock_skew_offset_ns=-25"));
    assert!(with_skew.contains("clock_drift_rate=999/1000"));
    assert_ne!(
        ScenarioDef::from_canonical_material("crucible.test.clock-skew.public", &no_skew).id(),
        ScenarioDef::from_canonical_material("crucible.test.clock-skew.public", &with_skew).id(),
    );
}

#[test]
fn clock_skew_rejects_invalid_or_overflowing_time() {
    let invalid = ClockDriftRate {
        numerator: 1,
        denominator: 0,
    };
    let overflowing = ClockDriftRate {
        numerator: u64::MAX,
        denominator: 1,
    };

    assert_eq!(
        ClockDriftRate::new(1, 0),
        Err(TimeConversionError::InvalidDriftRate {
            drift_rate: invalid,
        })
    );
    assert_eq!(
        overflowing.apply_floor(VirtualInstant { nanos: 2 }),
        Err(TimeConversionError::GuestVisibleTimeOverflow {
            virtual_time: VirtualInstant { nanos: 2 },
            drift_rate: overflowing,
        })
    );
    assert_eq!(
        NodeClockSkew {
            offset: SimOffset { nanos: 1 },
            drift_rate: ClockDriftRate::ONE,
        }
        .guest_visible_time(VirtualInstant { nanos: u64::MAX }),
        Err(TimeConversionError::GuestVisibleTimeOffsetOverflow {
            virtual_time: VirtualInstant { nanos: u64::MAX },
            offset: SimOffset { nanos: 1 },
        })
    );
    assert_eq!(
        NodeClockSkew {
            offset: SimOffset { nanos: 1 },
            drift_rate: invalid,
        }
        .scenario_hash_material(),
        Err(TimeConversionError::InvalidDriftRate {
            drift_rate: invalid,
        })
    );
}

fn drift_rate(numerator: u64, denominator: u64) -> ClockDriftRate {
    match ClockDriftRate::new(numerator, denominator) {
        Ok(rate) => rate,
        Err(error) => panic!("test drift rate should be valid: {error}"),
    }
}

fn material_with_skew(base: &str, skew: NodeClockSkew) -> String {
    match skew.scenario_hash_material() {
        Ok(Some(skew_material)) => format!("{base}\n{skew_material}"),
        Ok(None) => base.to_owned(),
        Err(error) => panic!("test clock skew material should be valid: {error}"),
    }
}
