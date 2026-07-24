//! Canonical per-node launch metadata rendering.

use super::{
    LaunchProfileError, MAX_ICOUNT_SHIFT, NodeClockSkewDeclaration, NodeIcountShift,
    validate_fixed_text,
};

pub(super) fn canonical_node_icount_shift_lines(
    scenario_shift: u8,
    node_shifts: &[NodeIcountShift],
) -> Result<Vec<String>, LaunchProfileError> {
    validate_icount_shift(scenario_shift)?;

    let mut ordered = Vec::with_capacity(node_shifts.len());
    for node_shift in node_shifts {
        validate_fixed_text("node_id", &node_shift.node_id)?;
        validate_icount_shift(node_shift.shift)?;
        if node_shift.shift != scenario_shift {
            return Err(LaunchProfileError::IcountShiftMismatch {
                node_id: node_shift.node_id.clone(),
                scenario_shift,
                node_shift: node_shift.shift,
            });
        }
        ordered.push((node_shift.node_id.clone(), node_shift.shift));
    }

    ordered.sort_by(|left, right| left.0.cmp(&right.0));
    for adjacent in ordered.windows(2) {
        if adjacent[0].0 == adjacent[1].0 {
            return Err(LaunchProfileError::DuplicateNodeIcountShift {
                node_id: adjacent[0].0.clone(),
            });
        }
    }

    Ok(ordered
        .into_iter()
        .map(|(node_id, shift)| format!("node_icount_shift[{node_id}]={shift}"))
        .collect())
}

pub(super) fn canonical_node_clock_skew_lines(
    node_clock_skews: &[NodeClockSkewDeclaration],
) -> Result<Vec<String>, LaunchProfileError> {
    let mut ordered = Vec::with_capacity(node_clock_skews.len());
    for node_clock_skew in node_clock_skews {
        validate_fixed_text("node_id", &node_clock_skew.node_id)?;
        if node_clock_skew.skew.drift_rate.denominator == 0 {
            return Err(LaunchProfileError::InvalidNodeClockDriftRate {
                node_id: node_clock_skew.node_id.clone(),
                numerator: node_clock_skew.skew.drift_rate.numerator,
                denominator: node_clock_skew.skew.drift_rate.denominator,
            });
        }
        ordered.push((node_clock_skew.node_id.clone(), node_clock_skew.skew));
    }

    ordered.sort_by(|left, right| left.0.cmp(&right.0));
    for adjacent in ordered.windows(2) {
        if adjacent[0].0 == adjacent[1].0 {
            return Err(LaunchProfileError::DuplicateNodeClockSkew {
                node_id: adjacent[0].0.clone(),
            });
        }
    }

    let mut lines = Vec::new();
    for (node_id, skew) in ordered {
        if skew.is_perfect() {
            continue;
        }
        lines.push(format!(
            "node_clock_skew_offset_ns[{node_id}]={}",
            skew.offset.nanos
        ));
        lines.push(format!(
            "node_clock_drift_rate[{node_id}]={}/{}",
            skew.drift_rate.numerator, skew.drift_rate.denominator
        ));
        lines.push(format!("node_clock_drift_rounding[{node_id}]=floor"));
        lines.push(format!(
            "node_clock_skew_applies_to[{node_id}]=guest-visible-only"
        ));
        lines.push(format!(
            "node_clock_skew_scheduling_axis[{node_id}]=unskewed-icount-derived"
        ));
    }

    Ok(lines)
}

pub(super) fn validate_icount_shift(shift: u8) -> Result<u8, LaunchProfileError> {
    if shift <= MAX_ICOUNT_SHIFT {
        Ok(shift)
    } else {
        Err(LaunchProfileError::IcountShiftTooLarge { shift })
    }
}
