//! Checkpoint-segment replay integration for divergence bisection.

use std::error::Error;
use std::fmt;

use crate::fingerprint::FingerprintStream;
use crate::segment_replay::{
    ReplayCheckpoint, ReplaySegment, ReplaySegmentOutput, SegmentReplayError,
    replay_checkpoint_segments,
};

use super::{
    DecisionTraceEntry, DivergenceBisectionError, DivergenceBisectionReport, DivergenceSide,
    DivergenceStateDump, bisect_diverging_runs,
};

/// A divergence report proven invariant across replay segment counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentedDivergenceBisectionReport {
    /// Canonical divergence report shared by every tested segment count.
    pub divergence: DivergenceBisectionReport,
    /// Non-zero segment-count requests exercised in the supplied order.
    pub segment_counts: Vec<usize>,
}

/// A segment-parallel divergence-bisection failure.
#[derive(Debug, PartialEq, Eq)]
pub enum SegmentedDivergenceBisectionError<ReplayError> {
    /// No segment count was supplied for the invariance check.
    MissingSegmentCount,
    /// A requested segment count was zero.
    ZeroSegmentCount,
    /// Replaying one side to a bisection probe coordinate failed.
    Replay {
        /// Divergence side whose replay failed.
        side: DivergenceSide,
        /// Probe coordinate requested by bisection.
        target: u64,
        /// Segment coordinator or backend failure.
        source: SegmentReplayError<ReplayError>,
    },
    /// Fingerprint localization or fine bisection failed.
    Bisection {
        /// Segment-count request active when bisection failed.
        segment_count: usize,
        /// Underlying divergence-bisection failure.
        source: DivergenceBisectionError,
    },
    /// Different segment counts located different divergence coordinates.
    CoordinateChanged {
        /// Segment count that established the canonical coordinate.
        baseline_segment_count: usize,
        /// Canonical first-different coordinate.
        baseline_coordinate: u64,
        /// Segment count that produced a different coordinate.
        segment_count: usize,
        /// First-different coordinate produced by `segment_count`.
        coordinate: u64,
    },
}

impl<ReplayError: fmt::Display> fmt::Display for SegmentedDivergenceBisectionError<ReplayError> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSegmentCount => {
                f.write_str("segment-parallel divergence bisection requires a segment count")
            }
            Self::ZeroSegmentCount => {
                f.write_str("divergence-bisection segment count must be non-zero")
            }
            Self::Replay {
                side,
                target,
                source,
            } => write!(
                f,
                "{side:?} segment replay to divergence probe {target} failed: {source}"
            ),
            Self::Bisection {
                segment_count,
                source,
            } => write!(
                f,
                "divergence bisection with segment count {segment_count} failed: {source}"
            ),
            Self::CoordinateChanged {
                baseline_segment_count,
                baseline_coordinate,
                segment_count,
                coordinate,
            } => write!(
                f,
                "segment count {segment_count} located divergence {coordinate}, but count {baseline_segment_count} located {baseline_coordinate}"
            ),
        }
    }
}

impl<ReplayError> Error for SegmentedDivergenceBisectionError<ReplayError>
where
    ReplayError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Replay { source, .. } => Some(source),
            Self::Bisection { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Bisects divergent runs through checkpoint-segment parallel replay.
///
/// Each match probe replays both sides to the requested coordinate. Segment
/// outputs are checkpoint-validated and canonically joined by
/// [`replay_checkpoint_segments`]. The full bisection is repeated for every
/// requested segment count and must locate one identical coordinate.
///
/// # Errors
///
/// Returns [`SegmentedDivergenceBisectionError`] when segment counts are missing
/// or zero, a segment replay fails, ordinary divergence bisection fails, or a
/// segment count changes the located divergence coordinate.
// crucible-lint: allow rust-allow -- replay inputs remain explicit so callers cannot accidentally swap left/right state or omit checkpoint validation material.
#[allow(clippy::too_many_arguments)]
pub fn bisect_diverging_runs_with_segment_replay<State, ReplayError, Replay, Dump>(
    left: &FingerprintStream,
    right: &FingerprintStream,
    left_decisions: &[DecisionTraceEntry],
    right_decisions: &[DecisionTraceEntry],
    left_checkpoints: &[ReplayCheckpoint<State>],
    right_checkpoints: &[ReplayCheckpoint<State>],
    segment_counts: &[usize],
    replay: Replay,
    mut dump_at: Dump,
) -> Result<SegmentedDivergenceBisectionReport, SegmentedDivergenceBisectionError<ReplayError>>
where
    State: Clone + Eq + Send + Sync,
    ReplayError: Send,
    Replay: Fn(DivergenceSide, &ReplaySegment<State>) -> Result<ReplaySegmentOutput<State>, ReplayError>
        + Sync,
    Dump: FnMut(DivergenceSide, u64) -> DivergenceStateDump,
{
    if segment_counts.is_empty() {
        return Err(SegmentedDivergenceBisectionError::MissingSegmentCount);
    }
    if segment_counts.contains(&0) {
        return Err(SegmentedDivergenceBisectionError::ZeroSegmentCount);
    }

    let mut baseline: Option<(usize, DivergenceBisectionReport)> = None;
    for &segment_count in segment_counts {
        let mut replay_failure = None;
        let bisection = bisect_diverging_runs(
            left,
            right,
            left_decisions,
            right_decisions,
            |target| {
                if replay_failure.is_some() {
                    return false;
                }
                let left_replay = replay_checkpoint_segments(
                    left_checkpoints,
                    target,
                    segment_count,
                    |segment| replay(DivergenceSide::Left, segment),
                );
                let left_replay = match left_replay {
                    Ok(report) => report,
                    Err(source) => {
                        replay_failure = Some((DivergenceSide::Left, target, source));
                        return false;
                    }
                };
                let right_replay = replay_checkpoint_segments(
                    right_checkpoints,
                    target,
                    segment_count,
                    |segment| replay(DivergenceSide::Right, segment),
                );
                let right_replay = match right_replay {
                    Ok(report) => report,
                    Err(source) => {
                        replay_failure = Some((DivergenceSide::Right, target, source));
                        return false;
                    }
                };
                left_replay.final_state == right_replay.final_state
                    && left_replay.canonical_log == right_replay.canonical_log
            },
            &mut dump_at,
        );
        if let Some((side, target, source)) = replay_failure {
            return Err(SegmentedDivergenceBisectionError::Replay {
                side,
                target,
                source,
            });
        }
        let report = bisection.map_err(|source| SegmentedDivergenceBisectionError::Bisection {
            segment_count,
            source,
        })?;

        if let Some((baseline_segment_count, baseline_report)) = &baseline {
            if report.first_different_icount != baseline_report.first_different_icount {
                return Err(SegmentedDivergenceBisectionError::CoordinateChanged {
                    baseline_segment_count: *baseline_segment_count,
                    baseline_coordinate: baseline_report.first_different_icount,
                    segment_count,
                    coordinate: report.first_different_icount,
                });
            }
        } else {
            baseline = Some((segment_count, report.clone()));
        }
    }

    let Some((_, divergence)) = baseline else {
        return Err(SegmentedDivergenceBisectionError::MissingSegmentCount);
    };
    Ok(SegmentedDivergenceBisectionReport {
        divergence,
        segment_counts: segment_counts.to_vec(),
    })
}
