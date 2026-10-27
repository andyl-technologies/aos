//! Segment storage and live trace state owned by one fault continuation.
//!
//! A continuation records one resolved-effect trace and may replay another.
//! Neither trace is held in memory: the recording writer seals into the
//! storage's recording sink, and the replay reader decodes one segment at a
//! time from the replay sources. Checkpoints carry only the writer position
//! and the replay cursor, so restoring a continuation needs the same storage.

use std::sync::Arc;

use super::*;
use crate::segment_store::{SegmentSink, SegmentSource, SegmentSources, SharedSegmentStore};

/// Segment stores used by one fault continuation's resolved-effect traces.
///
/// The recording sink receives every segment the continuation seals. The
/// replay sources hold the segments of an installed replay trace; the
/// recording sink is consulted after them, so a continuation restored in the
/// store that recorded its replay input needs no separate replay source.
#[derive(Clone)]
pub struct FaultTraceStorage {
    recording: Arc<dyn SegmentSink>,
    replay: SegmentSources,
}

impl FaultTraceStorage {
    /// Records into `recording` and reads replay segments from it.
    #[must_use]
    pub fn new(recording: Arc<dyn SegmentSink>) -> Self {
        Self {
            recording,
            replay: SegmentSources::default(),
        }
    }

    /// Records into a private in-memory store.
    ///
    /// Suitable for bounded in-process executions and tests; production
    /// executors supply quota-accounted attempt storage instead.
    #[must_use]
    pub fn in_memory() -> Self {
        Self::new(Arc::new(SharedSegmentStore::new()))
    }

    /// Adds the stores that hold an installed replay trace's segments.
    #[must_use]
    pub fn with_replay_segments(mut self, segments: SegmentSources) -> Self {
        self.replay.extend(segments);
        self
    }

    /// Returns the sink that receives recorded segments.
    #[must_use]
    pub const fn recording(&self) -> &Arc<dyn SegmentSink> {
        &self.recording
    }

    /// Returns every store a replay segment may be read from.
    #[must_use]
    pub fn replay_segments(&self) -> SegmentSources {
        let mut segments = self.replay.clone();
        segments.push(Arc::new(RecordingSource(Arc::clone(&self.recording))));
        segments
    }
}

impl Default for FaultTraceStorage {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl fmt::Debug for FaultTraceStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FaultTraceStorage")
            .field("replay", &self.replay)
            .finish_non_exhaustive()
    }
}

/// Read access to a recording sink through the shared source trait.
struct RecordingSource(Arc<dyn SegmentSink>);

impl SegmentSource for RecordingSource {
    fn segment(&self, id: crucible_store::content_store::ContentId) -> std::io::Result<Vec<u8>> {
        self.0.segment(id)
    }
}

/// The live trace state of one continuation, kept outside its checkpoint.
///
/// Owners that restore their evaluator for every boundary move this state in
/// and out of the evaluator instead of round-tripping it through a cloned
/// checkpoint, so per-evaluation work never copies the open tail.
#[derive(Clone, Debug)]
pub(crate) struct FaultTraceState {
    pub(crate) recorded: ResolvedEffectTraceWriter,
    pub(crate) replay: Option<ResolvedEffectTraceReader>,
}

impl FaultTraceState {
    /// Starts an empty recording with no replay installed.
    pub(crate) fn new(storage: &FaultTraceStorage, resource_limits: FaultResourceLimits) -> Self {
        Self {
            recorded: ResolvedEffectTraceWriter::new(
                Arc::clone(storage.recording()),
                resource_limits,
            ),
            replay: None,
        }
    }

    /// Restores the recording position and replay cursor of a checkpoint.
    pub(crate) fn restore(
        storage: &FaultTraceStorage,
        checkpoint: &FaultRuntimeCheckpoint,
    ) -> Result<Self, FaultRuntimeError> {
        let recorded = ResolvedEffectTraceWriter::restore(
            Arc::clone(storage.recording()),
            checkpoint.resource_limits,
            checkpoint.recorded.clone(),
        )?;
        let replay = checkpoint
            .replay
            .as_ref()
            .map(|cursor| {
                ResolvedEffectTraceReader::restore(
                    cursor,
                    storage.replay_segments(),
                    checkpoint.resource_limits,
                )
            })
            .transpose()?;
        Ok(Self { recorded, replay })
    }

    /// Writes the recording position and replay cursor into `checkpoint`.
    pub(crate) fn fill(&self, checkpoint: &mut FaultRuntimeCheckpoint) {
        checkpoint.recorded = self.recorded.position().clone();
        checkpoint.replay = self
            .replay
            .as_ref()
            .map(ResolvedEffectTraceReader::replay_cursor);
    }

    /// Returns the recorded trace in `mode`.
    ///
    /// Recomputed and locked traces share the writer's sealed segments. An
    /// outcome-only network trace keeps only network-keyed work items and is
    /// re-segmented by the ordinary seal rule into the same sink, so its item
    /// indices are its own.
    pub(crate) fn recorded_trace(
        &self,
        mode: FaultReplayMode,
    ) -> Result<ResolvedEffectTrace, FaultRuntimeError> {
        match mode {
            FaultReplayMode::RecomputedCause | FaultReplayMode::LockedEffect => {
                self.recorded.export(mode)
            }
            FaultReplayMode::OutcomeOnlyNetwork(_) => {
                let mut filtered = ResolvedEffectTraceWriter::new(
                    Arc::clone(self.recorded.sink()),
                    self.recorded.resource_limits(),
                );
                self.recorded.try_for_each_item(|item| {
                    if item.network_frame_key.is_none() {
                        return Ok::<(), FaultRuntimeError>(());
                    }
                    if item
                        .records
                        .iter()
                        .any(|record| record.effect.descriptor().adapter != FaultAdapter::Network)
                    {
                        return Err(FaultRuntimeError::InvalidReplayTrace);
                    }
                    filtered.append(item.clone())
                })?;
                filtered.finish(mode)
            }
        }
    }
}
