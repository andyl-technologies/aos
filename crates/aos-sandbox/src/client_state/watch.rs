//! Bound bootstrap and resume reduction for established public watch events.
//!
//! Query bindings travel with snapshot watermarks and cursors. The sequence
//! contract is explicit: filtered streams may require only strict monotonicity,
//! while a server that advertises a stream-local contiguous sequence can opt in
//! to gap detection. Server `resync_required` always forces a fresh bootstrap.

use std::collections::{BTreeMap, BTreeSet};

use aos_proto::aos::sandbox::v1::EventKind;

use crate::controller_query::event::{
    BoundWatchCursorV1, BoundWatchWatermarkV1, CheckedWatchEventV1, InvalidWatchEvent,
};
use crate::controller_query::model::{ClientStateItem, QueryBindingV1, checked_item_cost};

/// Maximum resources in one bootstrap chunk.
pub const MAXIMUM_WATCH_CHUNK_ITEMS: usize = 1_024;
/// Maximum protobuf bytes in one bootstrap chunk.
pub const MAXIMUM_WATCH_CHUNK_BYTES: usize = 16 * 1024 * 1024;
/// Maximum resources accumulated before snapshot completion.
pub const MAXIMUM_WATCH_BOOTSTRAP_ITEMS: usize = 65_536;
/// Maximum protobuf bytes accumulated before snapshot completion.
pub const MAXIMUM_WATCH_BOOTSTRAP_BYTES: usize = 64 * 1024 * 1024;
/// Maximum live events retained by one reducer instance.
pub const MAXIMUM_RETAINED_WATCH_EVENTS: usize = 65_536;
/// Maximum protobuf bytes retained for event deduplication.
pub const MAXIMUM_RETAINED_WATCH_BYTES: usize = 64 * 1024 * 1024;

/// Reports invalid watch construction or use.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WatchError {
    /// A configured item/event/byte bound is zero or exceeds its ceiling.
    #[error("watch reducer bound is invalid")]
    InvalidBound,
    /// A snapshot chunk or established event is malformed or oversized.
    #[error("watch response is invalid")]
    InvalidResponse,
    /// Input was supplied after the stream terminated.
    #[error("watch reducer is already terminal")]
    AlreadyTerminal,
    /// A required rolling-upgrade extension is not registered by this client.
    #[error("watch event requires an unsupported observation extension")]
    UnsupportedRequiredExtension,
}

impl From<InvalidWatchEvent> for WatchError {
    fn from(value: InvalidWatchEvent) -> Self {
        if value == InvalidWatchEvent::UnsupportedRequiredExtension {
            Self::UnsupportedRequiredExtension
        } else {
            Self::InvalidResponse
        }
    }
}

/// Defines how sequence numbers behave within this exact bound stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamSequenceContractV1 {
    /// Values strictly increase; filtered-out events may create numeric gaps.
    Monotone,
    /// Values are contiguous within this exact query-bound stream.
    Contiguous,
}

/// Stores the last fully applied query-bound watch position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchResumePointV1 {
    cursor: BoundWatchCursorV1,
    sequence: u64,
}

impl WatchResumePointV1 {
    pub(crate) const fn from_checkpoint(cursor: BoundWatchCursorV1, sequence: u64) -> Self {
        Self { cursor, sequence }
    }

    /// Returns the complete normalized query binding.
    #[must_use]
    pub const fn binding(&self) -> QueryBindingV1 {
        self.cursor.binding()
    }

    /// Returns the last fully applied cursor.
    #[must_use]
    pub const fn cursor(&self) -> &BoundWatchCursorV1 {
        &self.cursor
    }

    /// Returns the last fully applied stream sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Stores one checked bounded snapshot chunk.
#[derive(Clone, Debug, PartialEq)]
pub struct WatchSnapshotChunkV1<T> {
    binding: QueryBindingV1,
    watermark: BoundWatchWatermarkV1,
    index: u32,
    items: Vec<T>,
    item_bytes: usize,
}

impl<T: ClientStateItem> WatchSnapshotChunkV1<T> {
    /// Checks one server snapshot chunk under its receiving query binding.
    ///
    /// # Errors
    ///
    /// Returns [`WatchError::InvalidResponse`] for empty or oversized chunks,
    /// malformed watermarks, or item byte-cost overflow.
    pub fn from_response(
        binding: QueryBindingV1,
        watermark: Vec<u8>,
        index: u32,
        items: Vec<T>,
    ) -> Result<Self, WatchError> {
        if items.is_empty() || items.len() > MAXIMUM_WATCH_CHUNK_ITEMS {
            return Err(WatchError::InvalidResponse);
        }
        let item_bytes = items.iter().try_fold(0_usize, |total, item| {
            total
                .checked_add(checked_item_cost(item).map_err(|_| WatchError::InvalidResponse)?)
                .ok_or(WatchError::InvalidResponse)
        })?;
        if item_bytes > MAXIMUM_WATCH_CHUNK_BYTES {
            return Err(WatchError::InvalidResponse);
        }
        Ok(Self {
            binding,
            watermark: BoundWatchWatermarkV1::from_response(binding, watermark)?,
            index,
            items,
            item_bytes,
        })
    }
}

/// Identifies why the server requires a fresh bootstrap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerResyncReasonV1 {
    /// The supplied cursor is expired or unknown.
    CursorUnavailable,
    /// The stream epoch changed.
    EpochChanged,
    /// The bound authorization revision cannot be replayed.
    AuthorizationRevisionChanged,
    /// Retention compaction removed required events.
    Compacted,
    /// A slow consumer was evicted.
    SlowConsumerEvicted,
    /// Query, principal, visibility, authorization, or schema binding changed.
    BindingChanged,
}

/// Stores one semantic watch-stream input.
#[derive(Clone, Debug, PartialEq)]
pub enum WatchInputV1<T> {
    /// One chunk of an initial snapshot.
    SnapshotChunk(WatchSnapshotChunkV1<T>),
    /// One established snapshot-complete or live event.
    Event(CheckedWatchEventV1),
    /// The server cannot continue the cursor and requires a fresh bootstrap.
    ResyncRequired(ServerResyncReasonV1),
    /// Authorization narrowed; the stream ends without identifying concealed resources.
    AuthorizationChanged,
}

/// Identifies why a watch reducer stopped.
#[derive(Clone, Debug, PartialEq)]
pub enum WatchTerminationV1 {
    /// A fresh list/bootstrap is required for this reason.
    RelistRequired(WatchRelistReasonV1),
    /// Authorization changed and the stream ended without disclosure.
    AuthorizationChanged,
    /// Bounded deduplication capacity was reached; resume from this exact cursor.
    ResumeRequired(WatchResumePointV1),
}

/// Identifies why incremental stream state can no longer be trusted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchRelistReasonV1 {
    /// The server explicitly rejected the cursor.
    Server(ServerResyncReasonV1),
    /// A stream-local contiguous sequence skipped an event.
    CursorGap,
    /// A binding, watermark, cursor, mode, or sequence was substituted.
    StreamDiscontinuity,
    /// A stable event identity carried different content.
    EventEquivocation,
    /// Bootstrap resources exceeded the caller-selected item or byte bound.
    BootstrapCapacityExceeded,
}

/// Stores a newly completed snapshot baseline.
#[derive(Clone, Debug, PartialEq)]
pub struct CompletedWatchBootstrapV1<T> {
    watermark: BoundWatchWatermarkV1,
    resume: WatchResumePointV1,
    items: Vec<T>,
    item_bytes: usize,
}

impl<T> CompletedWatchBootstrapV1<T> {
    /// Returns the immutable query-bound bootstrap watermark.
    #[must_use]
    pub const fn watermark(&self) -> &BoundWatchWatermarkV1 {
        &self.watermark
    }

    /// Returns the exact cursor from which live events continue.
    #[must_use]
    pub const fn resume(&self) -> &WatchResumePointV1 {
        &self.resume
    }

    /// Returns the complete baseline resources.
    #[must_use]
    pub fn items(&self) -> &[T] {
        &self.items
    }

    /// Returns the checked aggregate protobuf byte cost.
    #[must_use]
    pub const fn item_bytes(&self) -> usize {
        self.item_bytes
    }
}

/// Reports the result of one successful watch reduction.
#[derive(Clone, Debug, PartialEq)]
pub enum WatchApplyOutcomeV1<T> {
    /// A bootstrap chunk was retained but is not yet a complete baseline.
    SnapshotChunkAccepted,
    /// The snapshot-complete event exposed this complete baseline.
    BootstrapComplete(CompletedWatchBootstrapV1<T>),
    /// A fresh live public event was applied.
    EventApplied(CheckedWatchEventV1),
    /// An exact at-least-once event replay was ignored.
    Replay,
    /// The stream reached a terminal reducer state.
    Terminated(WatchTerminationV1),
}

#[derive(Clone, Debug, PartialEq)]
enum WatchModeV1<T> {
    Bootstrap {
        watermark: Option<BoundWatchWatermarkV1>,
        next_chunk_index: u32,
        items: Vec<T>,
        item_bytes: usize,
    },
    Live,
}

/// Reduces one bounded bootstrap or resumed watch stream.
#[derive(Clone, Debug, PartialEq)]
pub struct WatchReducerV1<T> {
    binding: QueryBindingV1,
    sequence_contract: StreamSequenceContractV1,
    mode: WatchModeV1<T>,
    maximum_bootstrap_items: usize,
    maximum_bootstrap_bytes: usize,
    maximum_live_events: usize,
    maximum_live_bytes: usize,
    resume: Option<WatchResumePointV1>,
    retained_events: BTreeMap<[u8; 16], CheckedWatchEventV1>,
    retained_cursors: BTreeSet<Vec<u8>>,
    retained_event_bytes: usize,
    termination: Option<WatchTerminationV1>,
}

impl<T> WatchReducerV1<T> {
    /// Creates an initial bootstrap reducer.
    ///
    /// # Errors
    ///
    /// Returns [`WatchError::InvalidBound`] for zero or excessive bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn bootstrap(
        binding: QueryBindingV1,
        sequence_contract: StreamSequenceContractV1,
        maximum_bootstrap_items: usize,
        maximum_bootstrap_bytes: usize,
        maximum_live_events: usize,
        maximum_live_bytes: usize,
    ) -> Result<Self, WatchError> {
        validate_bounds(
            maximum_bootstrap_items,
            maximum_bootstrap_bytes,
            maximum_live_events,
            maximum_live_bytes,
        )?;
        Ok(Self {
            binding,
            sequence_contract,
            mode: WatchModeV1::Bootstrap {
                watermark: None,
                next_chunk_index: 0,
                items: Vec::new(),
                item_bytes: 0,
            },
            maximum_bootstrap_items,
            maximum_bootstrap_bytes,
            maximum_live_events,
            maximum_live_bytes,
            resume: None,
            retained_events: BTreeMap::new(),
            retained_cursors: BTreeSet::new(),
            retained_event_bytes: 0,
            termination: None,
        })
    }

    /// Creates a resume-only reducer from a fully applied query-bound cursor.
    ///
    /// # Errors
    ///
    /// Returns [`WatchError`] when the resume binding differs or live bounds
    /// are invalid.
    pub fn resume(
        binding: QueryBindingV1,
        sequence_contract: StreamSequenceContractV1,
        resume: WatchResumePointV1,
        maximum_live_events: usize,
        maximum_live_bytes: usize,
    ) -> Result<Self, WatchError> {
        validate_bounds(1, 1, maximum_live_events, maximum_live_bytes)?;
        if resume.binding() != binding {
            return Err(WatchError::InvalidResponse);
        }
        let retained_cursors = BTreeSet::from([resume.cursor().as_bytes().to_vec()]);
        Ok(Self {
            binding,
            sequence_contract,
            mode: WatchModeV1::Live,
            maximum_bootstrap_items: 1,
            maximum_bootstrap_bytes: 1,
            maximum_live_events,
            maximum_live_bytes,
            resume: Some(resume),
            retained_events: BTreeMap::new(),
            retained_cursors,
            retained_event_bytes: 0,
            termination: None,
        })
    }

    /// Returns the last fully applied cursor.
    #[must_use]
    pub const fn resume_point(&self) -> Option<&WatchResumePointV1> {
        self.resume.as_ref()
    }

    /// Returns the terminal state, if any.
    #[must_use]
    pub const fn termination(&self) -> Option<&WatchTerminationV1> {
        self.termination.as_ref()
    }
}

impl<T: ClientStateItem> WatchReducerV1<T> {
    /// Reduces one semantic stream input.
    ///
    /// Every semantic conflict becomes a terminal relist result, while malformed
    /// pre-reduction values return [`WatchError`] without mutation.
    ///
    /// # Errors
    ///
    /// Returns [`WatchError::AlreadyTerminal`] after stop.
    pub fn apply(&mut self, input: WatchInputV1<T>) -> Result<WatchApplyOutcomeV1<T>, WatchError> {
        if self.termination.is_some() {
            return Err(WatchError::AlreadyTerminal);
        }
        match input {
            WatchInputV1::SnapshotChunk(chunk) => self.apply_snapshot_chunk(chunk),
            WatchInputV1::Event(event) => self.apply_event(event),
            WatchInputV1::ResyncRequired(reason) => Ok(self.terminate(
                WatchTerminationV1::RelistRequired(WatchRelistReasonV1::Server(reason)),
            )),
            WatchInputV1::AuthorizationChanged => {
                Ok(self.terminate(WatchTerminationV1::AuthorizationChanged))
            }
        }
    }

    fn apply_snapshot_chunk(
        &mut self,
        chunk: WatchSnapshotChunkV1<T>,
    ) -> Result<WatchApplyOutcomeV1<T>, WatchError> {
        let (expected_index, watermark_matches, resulting_items, resulting_bytes) = match &self.mode
        {
            WatchModeV1::Bootstrap {
                watermark,
                next_chunk_index,
                items,
                item_bytes,
            } => (
                *next_chunk_index,
                watermark
                    .as_ref()
                    .is_none_or(|current| current == &chunk.watermark),
                items.len().checked_add(chunk.items.len()),
                item_bytes.checked_add(chunk.item_bytes),
            ),
            WatchModeV1::Live => {
                return Ok(self.discontinuity());
            }
        };
        if chunk.binding != self.binding
            || chunk.watermark.binding() != self.binding
            || chunk.index != expected_index
            || !watermark_matches
        {
            return Ok(self.discontinuity());
        }
        if resulting_items.is_none_or(|total| total > self.maximum_bootstrap_items)
            || resulting_bytes.is_none_or(|total| total > self.maximum_bootstrap_bytes)
        {
            return Ok(self.terminate(WatchTerminationV1::RelistRequired(
                WatchRelistReasonV1::BootstrapCapacityExceeded,
            )));
        }
        let following_index = expected_index
            .checked_add(1)
            .ok_or(WatchError::InvalidResponse)?;
        let next_bytes = resulting_bytes.ok_or(WatchError::InvalidResponse)?;
        let WatchModeV1::Bootstrap {
            watermark,
            next_chunk_index,
            items,
            item_bytes,
        } = &mut self.mode
        else {
            return Err(WatchError::InvalidResponse);
        };
        if watermark.is_none() {
            *watermark = Some(chunk.watermark);
        }
        items.extend(chunk.items);
        *item_bytes = next_bytes;
        *next_chunk_index = following_index;
        Ok(WatchApplyOutcomeV1::SnapshotChunkAccepted)
    }

    fn apply_event(
        &mut self,
        event: CheckedWatchEventV1,
    ) -> Result<WatchApplyOutcomeV1<T>, WatchError> {
        if event.cursor().binding() != self.binding {
            return Ok(self.discontinuity());
        }
        if let Some(exact_replay) = self
            .retained_events
            .get(&event.event_id())
            .map(|retained| retained == &event)
        {
            if exact_replay {
                return Ok(WatchApplyOutcomeV1::Replay);
            }
            return Ok(self.terminate(WatchTerminationV1::RelistRequired(
                WatchRelistReasonV1::EventEquivocation,
            )));
        }
        let bootstrap_watermark = match &self.mode {
            WatchModeV1::Bootstrap { watermark, .. } => Some(watermark.clone()),
            WatchModeV1::Live => None,
        };
        if let Some(expected_watermark) = bootstrap_watermark {
            if event.kind() != EventKind::EVENT_KIND_SNAPSHOT_COMPLETE
                || event
                    .watermark()
                    .is_none_or(|marker| marker.binding() != self.binding)
                || expected_watermark
                    .as_ref()
                    .is_some_and(|expected| event.watermark() != Some(expected))
            {
                return Ok(self.discontinuity());
            }
            self.complete_bootstrap(event)
        } else {
            if event.kind() == EventKind::EVENT_KIND_SNAPSHOT_COMPLETE {
                return Ok(self.discontinuity());
            }
            self.apply_live_event(event)
        }
    }

    fn complete_bootstrap(
        &mut self,
        event: CheckedWatchEventV1,
    ) -> Result<WatchApplyOutcomeV1<T>, WatchError> {
        let event_bytes = event.encoded_byte_cost();
        if event_bytes > self.maximum_live_bytes || self.maximum_live_events == 0 {
            return Ok(self.discontinuity());
        }
        let marker = event
            .watermark()
            .cloned()
            .ok_or(WatchError::InvalidResponse)?;
        let prior_mode = std::mem::replace(&mut self.mode, WatchModeV1::Live);
        let WatchModeV1::Bootstrap {
            items, item_bytes, ..
        } = prior_mode
        else {
            return Err(WatchError::InvalidResponse);
        };
        let resume = WatchResumePointV1 {
            cursor: event.cursor().clone(),
            sequence: event.sequence(),
        };
        let completed = CompletedWatchBootstrapV1 {
            watermark: marker,
            resume: resume.clone(),
            items,
            item_bytes,
        };
        self.retained_event_bytes = event_bytes;
        self.retained_cursors
            .insert(event.cursor().as_bytes().to_vec());
        self.retained_events.insert(event.event_id(), event);
        self.resume = Some(resume);
        Ok(WatchApplyOutcomeV1::BootstrapComplete(completed))
    }

    fn apply_live_event(
        &mut self,
        event: CheckedWatchEventV1,
    ) -> Result<WatchApplyOutcomeV1<T>, WatchError> {
        let Some(previous) = &self.resume else {
            return Ok(self.discontinuity());
        };
        if self.retained_cursors.contains(event.cursor().as_bytes())
            || event.sequence() <= previous.sequence()
        {
            return Ok(self.discontinuity());
        }
        if self.sequence_contract == StreamSequenceContractV1::Contiguous
            && previous
                .sequence()
                .checked_add(1)
                .is_none_or(|expected| event.sequence() != expected)
        {
            return Ok(self.terminate(WatchTerminationV1::RelistRequired(
                WatchRelistReasonV1::CursorGap,
            )));
        }
        let event_bytes = event.encoded_byte_cost();
        let resulting_bytes = self.retained_event_bytes.checked_add(event_bytes);
        if self.retained_events.len() >= self.maximum_live_events
            || resulting_bytes.is_none_or(|total| total > self.maximum_live_bytes)
        {
            let resume = previous.clone();
            return Ok(self.terminate(WatchTerminationV1::ResumeRequired(resume)));
        }

        let resume = WatchResumePointV1 {
            cursor: event.cursor().clone(),
            sequence: event.sequence(),
        };
        self.retained_event_bytes = resulting_bytes.ok_or(WatchError::InvalidResponse)?;
        self.retained_cursors
            .insert(event.cursor().as_bytes().to_vec());
        self.retained_events.insert(event.event_id(), event.clone());
        self.resume = Some(resume);
        Ok(WatchApplyOutcomeV1::EventApplied(event))
    }

    fn discontinuity(&mut self) -> WatchApplyOutcomeV1<T> {
        self.terminate(WatchTerminationV1::RelistRequired(
            WatchRelistReasonV1::StreamDiscontinuity,
        ))
    }

    fn terminate(&mut self, termination: WatchTerminationV1) -> WatchApplyOutcomeV1<T> {
        self.termination = Some(termination.clone());
        WatchApplyOutcomeV1::Terminated(termination)
    }
}

fn validate_bounds(
    maximum_bootstrap_items: usize,
    maximum_bootstrap_bytes: usize,
    maximum_live_events: usize,
    maximum_live_bytes: usize,
) -> Result<(), WatchError> {
    if maximum_bootstrap_items == 0
        || maximum_bootstrap_items > MAXIMUM_WATCH_BOOTSTRAP_ITEMS
        || maximum_bootstrap_bytes == 0
        || maximum_bootstrap_bytes > MAXIMUM_WATCH_BOOTSTRAP_BYTES
        || maximum_live_events == 0
        || maximum_live_events > MAXIMUM_RETAINED_WATCH_EVENTS
        || maximum_live_bytes == 0
        || maximum_live_bytes > MAXIMUM_RETAINED_WATCH_BYTES
    {
        Err(WatchError::InvalidBound)
    } else {
        Ok(())
    }
}
