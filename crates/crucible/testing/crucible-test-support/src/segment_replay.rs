//! Checkpoint-segment parallel replay and deterministic joining.
//!
//! A replay suffix is represented by an ordered set of realizable checkpoints:
//!
//! ```text
//! checkpoint 0 -> checkpoint 1 -> ... -> target
//! ```
//!
//! Each arrow is replayed on its own host worker. The coordinator validates the
//! state at every checkpoint boundary and joins canonical-log entries in segment
//! order, so host completion order cannot become observable.

use std::error::Error;
use std::fmt;
use std::thread;

/// A realizable replay checkpoint at one canonical coordinate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayCheckpoint<State> {
    /// Canonical coordinate at which the checkpoint was materialized.
    pub coordinate: u64,
    /// Exact state restored when replay starts at this checkpoint.
    pub state: State,
}

/// One canonical event emitted while replaying a checkpoint segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayLogEntry {
    /// Canonical coordinate at which the event becomes observable.
    pub coordinate: u64,
    /// Canonical encoded event bytes.
    pub canonical_bytes: Vec<u8>,
}

/// One independently replayable checkpoint segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplaySegment<State> {
    /// Stable segment index in canonical replay order.
    pub index: usize,
    /// Inclusive start checkpoint coordinate.
    pub start_coordinate: u64,
    /// Inclusive target coordinate for this segment.
    pub end_coordinate: u64,
    /// Exact state restored at the start checkpoint.
    pub start_state: State,
}

/// State and canonical-log output from one replay segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplaySegmentOutput<State> {
    /// Exact state after replay reaches the segment end coordinate.
    pub end_state: State,
    /// Canonical events emitted in coordinate order during this segment.
    pub canonical_log: Vec<ReplayLogEntry>,
}

/// Deterministically joined output from a segment-parallel replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentReplayReport<State> {
    /// Exact state at the requested replay target.
    pub final_state: State,
    /// Canonical log joined in segment rather than worker-completion order.
    pub canonical_log: Vec<ReplayLogEntry>,
    /// Number of checkpoint segments replayed concurrently.
    pub segment_count: usize,
}

/// A checkpoint-segment replay or join failure.
#[derive(Debug, PartialEq, Eq)]
pub enum SegmentReplayError<ReplayError> {
    /// No realizable start checkpoint was supplied.
    MissingCheckpoint,
    /// Checkpoint coordinates were not strictly increasing.
    CheckpointOrder {
        /// Index of the first checkpoint that violates strict ordering.
        index: usize,
    },
    /// The target precedes the first replay checkpoint.
    TargetBeforeStart {
        /// First realizable checkpoint coordinate.
        start: u64,
        /// Requested target coordinate.
        target: u64,
    },
    /// The requested maximum segment count was zero.
    ZeroSegmentCount,
    /// A replay worker returned an error.
    ReplayFailed {
        /// Canonical segment index.
        segment: usize,
        /// Backend-specific replay failure.
        source: ReplayError,
    },
    /// A replay worker panicked.
    WorkerPanicked {
        /// Canonical segment index.
        segment: usize,
    },
    /// A segment did not reproduce the next checkpoint's exact state.
    CheckpointStateMismatch {
        /// Canonical segment index.
        segment: usize,
        /// Coordinate of the checkpoint that failed validation.
        coordinate: u64,
    },
    /// A segment emitted a log entry outside its coordinate interval.
    LogEntryOutOfRange {
        /// Canonical segment index.
        segment: usize,
        /// Coordinate carried by the invalid log entry.
        coordinate: u64,
        /// Segment start coordinate.
        start: u64,
        /// Segment end coordinate.
        end: u64,
    },
    /// A segment's canonical log was not coordinate ordered.
    LogOrder {
        /// Canonical segment index.
        segment: usize,
        /// Earlier log coordinate.
        previous: u64,
        /// Later entry whose coordinate moved backwards.
        current: u64,
    },
}

impl<ReplayError: fmt::Display> fmt::Display for SegmentReplayError<ReplayError> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCheckpoint => f.write_str("segment replay requires a checkpoint"),
            Self::CheckpointOrder { index } => {
                write!(f, "replay checkpoint {index} is not strictly ordered")
            }
            Self::TargetBeforeStart { start, target } => write!(
                f,
                "replay target {target} precedes start checkpoint {start}"
            ),
            Self::ZeroSegmentCount => f.write_str("segment replay count must be non-zero"),
            Self::ReplayFailed { segment, source } => {
                write!(f, "replay segment {segment} failed: {source}")
            }
            Self::WorkerPanicked { segment } => {
                write!(f, "replay segment {segment} worker panicked")
            }
            Self::CheckpointStateMismatch {
                segment,
                coordinate,
            } => write!(
                f,
                "replay segment {segment} did not reproduce checkpoint {coordinate}"
            ),
            Self::LogEntryOutOfRange {
                segment,
                coordinate,
                start,
                end,
            } => write!(
                f,
                "replay segment {segment} log coordinate {coordinate} is outside ({start}, {end}]"
            ),
            Self::LogOrder {
                segment,
                previous,
                current,
            } => write!(
                f,
                "replay segment {segment} log moved backwards from {previous} to {current}"
            ),
        }
    }
}

impl<ReplayError> Error for SegmentReplayError<ReplayError>
where
    ReplayError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ReplayFailed { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Replays a suffix concurrently across realizable checkpoint segments.
///
/// `maximum_segments` selects up to that many ordered checkpoint starts while
/// always retaining the oldest supplied checkpoint. Supplying one therefore
/// performs the equivalent serial replay from the same ancestor; supplying the
/// checkpoint count uses every available segment.
///
/// # Errors
///
/// Returns [`SegmentReplayError`] when checkpoints are missing or unordered,
/// the target precedes the first checkpoint, the segment count is zero, a
/// worker fails or panics, a checkpoint boundary state differs, or a canonical
/// log is malformed.
pub fn replay_checkpoint_segments<State, ReplayError, Replay>(
    checkpoints: &[ReplayCheckpoint<State>],
    target: u64,
    maximum_segments: usize,
    replay: Replay,
) -> Result<SegmentReplayReport<State>, SegmentReplayError<ReplayError>>
where
    State: Clone + Eq + Send + Sync,
    ReplayError: Send,
    Replay: Fn(&ReplaySegment<State>) -> Result<ReplaySegmentOutput<State>, ReplayError> + Sync,
{
    validate_replay_request(checkpoints, target, maximum_segments)?;
    if let Some(first) = checkpoints
        .first()
        .filter(|checkpoint| checkpoint.coordinate == target)
    {
        return Ok(SegmentReplayReport {
            final_state: first.state.clone(),
            canonical_log: Vec::new(),
            segment_count: 0,
        });
    }
    let selected = selected_checkpoint_indices(checkpoints, target, maximum_segments);
    let segments = build_segments(checkpoints, target, &selected);

    let outputs = thread::scope(|scope| {
        let handles = segments
            .iter()
            .map(|segment| {
                let replay_ref = &replay;
                scope.spawn(move || replay_ref(segment))
            })
            .collect::<Vec<_>>();

        handles
            .into_iter()
            .enumerate()
            .map(|(segment, handle)| match handle.join() {
                Ok(Ok(output)) => Ok(output),
                Ok(Err(source)) => Err(SegmentReplayError::ReplayFailed { segment, source }),
                Err(_) => Err(SegmentReplayError::WorkerPanicked { segment }),
            })
            .collect::<Result<Vec<_>, _>>()
    })?;

    join_segment_outputs(checkpoints, target, &selected, &segments, outputs)
}

fn validate_replay_request<State, ReplayError>(
    checkpoints: &[ReplayCheckpoint<State>],
    target: u64,
    maximum_segments: usize,
) -> Result<(), SegmentReplayError<ReplayError>> {
    let Some(first) = checkpoints.first() else {
        return Err(SegmentReplayError::MissingCheckpoint);
    };
    if maximum_segments == 0 {
        return Err(SegmentReplayError::ZeroSegmentCount);
    }
    for (index, pair) in checkpoints.windows(2).enumerate() {
        if pair[0].coordinate >= pair[1].coordinate {
            return Err(SegmentReplayError::CheckpointOrder { index: index + 1 });
        }
    }
    if target < first.coordinate {
        return Err(SegmentReplayError::TargetBeforeStart {
            start: first.coordinate,
            target,
        });
    }
    Ok(())
}

fn selected_checkpoint_indices<State>(
    checkpoints: &[ReplayCheckpoint<State>],
    target: u64,
    maximum_segments: usize,
) -> Vec<usize> {
    let available = checkpoints
        .iter()
        .take_while(|checkpoint| checkpoint.coordinate < target)
        .count();
    let count = available.min(maximum_segments);
    if count == 1 {
        return vec![0];
    }

    (0..count)
        .map(|selection| selection * (available - 1) / (count - 1))
        .collect()
}

fn build_segments<State: Clone>(
    checkpoints: &[ReplayCheckpoint<State>],
    target: u64,
    selected: &[usize],
) -> Vec<ReplaySegment<State>> {
    selected
        .iter()
        .enumerate()
        .map(|(index, checkpoint_index)| {
            let checkpoint = &checkpoints[*checkpoint_index];
            let end_coordinate = selected
                .get(index + 1)
                .map_or(target, |next| checkpoints[*next].coordinate);
            ReplaySegment {
                index,
                start_coordinate: checkpoint.coordinate,
                end_coordinate,
                start_state: checkpoint.state.clone(),
            }
        })
        .collect()
}

fn join_segment_outputs<State, ReplayError>(
    checkpoints: &[ReplayCheckpoint<State>],
    target: u64,
    selected: &[usize],
    segments: &[ReplaySegment<State>],
    outputs: Vec<ReplaySegmentOutput<State>>,
) -> Result<SegmentReplayReport<State>, SegmentReplayError<ReplayError>>
where
    State: Clone + Eq,
{
    let mut canonical_log = Vec::new();
    let mut final_state = None;

    for (index, (segment, output)) in segments.iter().zip(outputs).enumerate() {
        validate_segment_log(segment, &output.canonical_log)?;
        let expected = selected
            .get(index + 1)
            .map(|next| &checkpoints[*next].state)
            .or_else(|| {
                checkpoints
                    .iter()
                    .find(|checkpoint| checkpoint.coordinate == target)
                    .map(|checkpoint| &checkpoint.state)
            });
        if expected.is_some_and(|state| state != &output.end_state) {
            return Err(SegmentReplayError::CheckpointStateMismatch {
                segment: index,
                coordinate: segment.end_coordinate,
            });
        }
        canonical_log.extend(output.canonical_log);
        final_state = Some(output.end_state);
    }

    let Some(final_state) = final_state else {
        return Err(SegmentReplayError::MissingCheckpoint);
    };
    Ok(SegmentReplayReport {
        final_state,
        canonical_log,
        segment_count: segments.len(),
    })
}

fn validate_segment_log<State, ReplayError>(
    segment: &ReplaySegment<State>,
    log: &[ReplayLogEntry],
) -> Result<(), SegmentReplayError<ReplayError>> {
    let mut previous = segment.start_coordinate;
    for entry in log {
        if entry.coordinate <= segment.start_coordinate || entry.coordinate > segment.end_coordinate
        {
            return Err(SegmentReplayError::LogEntryOutOfRange {
                segment: segment.index,
                coordinate: entry.coordinate,
                start: segment.start_coordinate,
                end: segment.end_coordinate,
            });
        }
        if entry.coordinate < previous {
            return Err(SegmentReplayError::LogOrder {
                segment: segment.index,
                previous,
                current: entry.coordinate,
            });
        }
        previous = entry.coordinate;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint(coordinate: u64) -> ReplayCheckpoint<u64> {
        ReplayCheckpoint {
            coordinate,
            state: coordinate,
        }
    }

    fn exact_segment(
        segment: &ReplaySegment<u64>,
    ) -> Result<ReplaySegmentOutput<u64>, &'static str> {
        Ok(ReplaySegmentOutput {
            end_state: segment.end_coordinate,
            canonical_log: ((segment.start_coordinate + 1)..=segment.end_coordinate)
                .map(|coordinate| ReplayLogEntry {
                    coordinate,
                    canonical_bytes: coordinate.to_le_bytes().to_vec(),
                })
                .collect(),
        })
    }

    #[test]
    fn serial_and_all_checkpoint_segments_join_identically() {
        let checkpoints = [checkpoint(0), checkpoint(5), checkpoint(10), checkpoint(15)];
        let serial = match replay_checkpoint_segments(&checkpoints, 20, 1, exact_segment) {
            Ok(report) => report,
            Err(error) => panic!("serial replay failed: {error}"),
        };
        let parallel = match replay_checkpoint_segments(&checkpoints, 20, 4, exact_segment) {
            Ok(report) => report,
            Err(error) => panic!("parallel replay failed: {error}"),
        };

        assert_eq!(serial.final_state, parallel.final_state);
        assert_eq!(serial.canonical_log, parallel.canonical_log);
        assert_eq!(serial.segment_count, 1);
        assert_eq!(parallel.segment_count, 4);
    }

    #[test]
    fn replay_at_start_uses_the_checkpoint_without_a_worker() {
        let checkpoints = [checkpoint(7)];
        let report = match replay_checkpoint_segments(&checkpoints, 7, 4, exact_segment) {
            Ok(report) => report,
            Err(error) => panic!("checkpoint-coordinate replay failed: {error}"),
        };

        assert_eq!(report.final_state, 7);
        assert!(report.canonical_log.is_empty());
        assert_eq!(report.segment_count, 0);
    }

    #[test]
    fn checkpoint_state_mismatch_fails_closed() {
        let checkpoints = [checkpoint(0), checkpoint(5), checkpoint(10)];
        let result = replay_checkpoint_segments(&checkpoints, 15, 3, |segment| {
            let mut output = exact_segment(segment)?;
            if segment.end_coordinate == 5 {
                output.end_state = 4;
            }
            Ok::<_, &'static str>(output)
        });
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("bad checkpoint boundary must fail"),
        };

        assert!(matches!(
            error,
            SegmentReplayError::CheckpointStateMismatch {
                segment: 0,
                coordinate: 5
            }
        ));
    }

    #[test]
    fn malformed_log_coordinate_fails_closed() {
        let checkpoints = [checkpoint(0)];
        let result = replay_checkpoint_segments(&checkpoints, 5, 1, |segment| {
            Ok::<_, &'static str>(ReplaySegmentOutput {
                end_state: 5,
                canonical_log: vec![ReplayLogEntry {
                    coordinate: segment.start_coordinate,
                    canonical_bytes: Vec::new(),
                }],
            })
        });
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("out-of-range log entry must fail"),
        };

        assert!(matches!(
            error,
            SegmentReplayError::LogEntryOutOfRange {
                segment: 0,
                coordinate: 0,
                start: 0,
                end: 5
            }
        ));
    }

    #[test]
    fn backend_failure_retains_canonical_segment_index() {
        let checkpoints = [checkpoint(0), checkpoint(5)];
        let result = replay_checkpoint_segments(&checkpoints, 10, 2, |segment| {
            if segment.index == 1 {
                Err("injected replay failure")
            } else {
                exact_segment(segment)
            }
        });
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("backend failure must propagate"),
        };

        assert!(matches!(
            error,
            SegmentReplayError::ReplayFailed {
                segment: 1,
                source: "injected replay failure"
            }
        ));
    }
}
