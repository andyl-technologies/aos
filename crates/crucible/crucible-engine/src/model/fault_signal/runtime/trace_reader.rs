//! Segmented resolved-effect traces as values: handles, readers, and bundles.
//!
//! [`ResolvedEffectTrace`] pairs a manifest with read handles to the stores
//! that hold its segments. Carrying one costs no segment copies, and every
//! read authenticates the segment it decodes. Consumers stream items one
//! segment at a time through [`ResolvedEffectTrace::items`], and fault replay
//! consumes a trace through [`ResolvedEffectTraceReader`], which holds one
//! decoded segment and a cursor.
//!
//! Some carriers have no segment store: a saved run artifact and a lifecycle
//! query response assembled by a client. They carry a bundle instead
//! (RFC-0020 section 15.8):
//!
//! ```text
//! "crucible.resolved-effect-trace-bundle.v1\0"
//! u32 manifest length, manifest leaf
//! u32 segment count
//! per segment, in manifest order: u32 length, encoded segment
//! ```
//!
//! All integers are big-endian. Decoding requires exactly the segments the
//! manifest references, in order, each deriving its referenced identity. A
//! bundle is a transport form and never enters production identity.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::trace_format::require_mode_item;
#[cfg(any(debug_assertions, feature = "test-support"))]
use super::trace_format::{encode_segment, encoded_item_len};
use super::trace_log::read_segment;
use super::*;
use crate::segment_store::{SegmentSink, SegmentSource, SegmentSources, SharedSegmentStore};

const BUNDLE_MAGIC: &[u8] = b"crucible.resolved-effect-trace-bundle.v1\0";

/// A segmented resolved-effect trace and read access to its segments.
///
/// Two traces are equal when their manifests are: a manifest names its
/// segments by content identity, and every read authenticates them.
#[derive(Clone, Debug)]
pub struct ResolvedEffectTrace {
    manifest: ResolvedEffectTraceManifest,
    segments: SegmentSources,
}

impl PartialEq for ResolvedEffectTrace {
    fn eq(&self, other: &Self) -> bool {
        self.manifest == other.manifest
    }
}

impl Eq for ResolvedEffectTrace {}

impl ResolvedEffectTrace {
    /// Pairs a manifest with the stores that hold its segments.
    ///
    /// Segments are authenticated when they are read, not here.
    #[must_use]
    pub const fn new(manifest: ResolvedEffectTraceManifest, segments: SegmentSources) -> Self {
        Self { manifest, segments }
    }

    /// Returns a trace with no work items.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError::InvalidReplayTrace`] for an unusable
    /// outcome-alignment mode.
    pub fn empty(mode: FaultReplayMode) -> Result<Self, FaultRuntimeError> {
        Ok(Self::new(
            ResolvedEffectTraceManifest::empty(mode)?,
            SegmentSources::default(),
        ))
    }

    /// Records `items` into a private in-memory store and returns the trace.
    ///
    /// Segments seal exactly where a live recording of the same items would
    /// seal, so the result's manifest equals that recording's manifest.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when an item is invalid, the items exceed
    /// `resource_limits`, or an item is invalid for `mode`.
    pub fn from_items(
        mode: FaultReplayMode,
        items: impl IntoIterator<Item = ResolvedReplayWorkItem>,
        resource_limits: FaultResourceLimits,
    ) -> Result<Self, FaultRuntimeError> {
        let mut writer =
            ResolvedEffectTraceWriter::new(Arc::new(SharedSegmentStore::new()), resource_limits);
        for item in items {
            require_mode_item(mode, &item)?;
            writer.append(item)?;
        }
        writer.finish(mode)
    }

    /// Records `items` into a private in-memory store under a small seal target.
    ///
    /// Production writers seal before a tail would exceed
    /// [`SEGMENT_TARGET_BYTES`](crate::segment_store::SEGMENT_TARGET_BYTES).
    /// Test fixtures pass a much smaller `segment_target_bytes` so a trace of
    /// many segments needs only a few kilobytes of items. The result is a
    /// valid trace whose seal points differ from a production recording of the
    /// same items, so it never stands in for production identity.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when an item is invalid or invalid for
    /// `mode`, a segment cannot be encoded or stored, or the items need more
    /// segments than one manifest may reference.
    #[cfg(any(debug_assertions, feature = "test-support"))]
    #[doc(hidden)]
    pub fn from_items_with_segment_target(
        mode: FaultReplayMode,
        items: impl IntoIterator<Item = ResolvedReplayWorkItem>,
        segment_target_bytes: usize,
    ) -> Result<Self, FaultRuntimeError> {
        let store = SharedSegmentStore::new();
        let mut segments = Vec::new();
        let mut open = Vec::new();
        let mut open_bytes = 0_usize;
        let mut first_item = 0_u64;

        for item in items {
            item.validate()?;
            require_mode_item(mode, &item)?;
            let bytes = encoded_item_len(&item)?;
            // The production seal rule, under the caller's target.
            if !open.is_empty() && open_bytes.saturating_add(bytes) > segment_target_bytes {
                segments.push(store_segment(&store, first_item, &open)?);
                first_item += open.len() as u64;
                open.clear();
                open_bytes = 0;
            }
            open_bytes = open_bytes.saturating_add(bytes);
            open.push(item);
        }
        if !open.is_empty() {
            segments.push(store_segment(&store, first_item, &open)?);
        }

        Ok(Self::new(
            ResolvedEffectTraceManifest::new(mode, segments)?,
            store.into(),
        ))
    }

    /// Pairs a manifest with its stores after authenticating every segment.
    ///
    /// Each segment is read and decoded once, one at a time.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when a referenced segment is absent,
    /// fails authentication, or carries an item invalid for the trace mode.
    pub fn referencing(
        manifest: ResolvedEffectTraceManifest,
        segments: SegmentSources,
    ) -> Result<Self, FaultRuntimeError> {
        let trace = Self::new(manifest, segments);
        trace.try_for_each_item(|_| Ok::<(), FaultRuntimeError>(()))?;
        Ok(trace)
    }

    /// Returns the manifest.
    #[must_use]
    pub const fn manifest(&self) -> &ResolvedEffectTraceManifest {
        &self.manifest
    }

    /// Returns the stores holding the referenced segments.
    #[must_use]
    pub const fn segments(&self) -> &SegmentSources {
        &self.segments
    }

    /// Splits the trace into its manifest and segment stores.
    #[must_use]
    pub fn into_parts(self) -> (ResolvedEffectTraceManifest, SegmentSources) {
        (self.manifest, self.segments)
    }

    /// Returns the replay mode.
    #[must_use]
    pub const fn mode(&self) -> FaultReplayMode {
        self.manifest.mode()
    }

    /// Returns the number of work items.
    #[must_use]
    pub const fn work_items(&self) -> u64 {
        self.manifest.work_items()
    }

    /// Returns whether the trace has no work items.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.manifest.work_items() == 0
    }

    /// Returns the same segments under another replay mode.
    ///
    /// # Errors
    ///
    /// Returns the failures of [`ResolvedEffectTraceManifest::with_mode`].
    pub fn with_mode(&self, mode: FaultReplayMode) -> Result<Self, FaultRuntimeError> {
        Ok(Self::new(
            self.manifest.with_mode(mode)?,
            self.segments.clone(),
        ))
    }

    /// Streams the work items in order, decoding one segment at a time.
    #[must_use]
    pub fn items(&self) -> ResolvedEffectTraceItems<'_> {
        ResolvedEffectTraceItems {
            trace: self,
            segment: 0,
            loaded: Vec::new().into_iter(),
            failed: false,
        }
    }

    /// Visits every work item in order, decoding one segment at a time.
    ///
    /// Each segment is authenticated against its reference before any of its
    /// items is visited, so a visitor never sees unauthenticated content.
    ///
    /// # Errors
    ///
    /// Returns an error converted from [`FaultRuntimeError`] when a segment
    /// is missing, fails authentication, or holds an item invalid for the
    /// trace mode, or the first error `visit` returns.
    pub fn try_for_each_item<E: From<FaultRuntimeError>>(
        &self,
        mut visit: impl FnMut(&ResolvedReplayWorkItem) -> Result<(), E>,
    ) -> Result<(), E> {
        for item in self.items() {
            visit(&item?)?;
        }
        Ok(())
    }

    /// Copies every referenced segment into `sink`, one at a time.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when a segment is absent, fails
    /// authentication, or cannot be stored.
    pub fn copy_into(&self, sink: &dyn SegmentSink) -> Result<(), FaultRuntimeError> {
        for segment in self.manifest.segments() {
            let bytes = self.read_bytes(segment)?;
            decode_resolved_effect_trace_segment(segment, &bytes)?;
            sink.put_segment(segment.id, &bytes).map_err(|error| {
                FaultRuntimeError::TraceStorage {
                    segment: segment.id.encode(),
                    reason: error.to_string(),
                }
            })?;
        }
        Ok(())
    }

    /// Returns the bundle form under a caller-selected byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError::CheckpointEncoding`] when the bundle would
    /// exceed `maximum_bytes`, or a segment read or authentication failure.
    pub fn to_bundle_bytes(&self, maximum_bytes: usize) -> Result<Vec<u8>, FaultRuntimeError> {
        let manifest = self.manifest.canonical_bytes()?;
        let segments = self.manifest.segments();
        let total = bundle_len(manifest.len(), segments);
        if total > maximum_bytes as u64 {
            return Err(FaultRuntimeError::CheckpointEncoding);
        }

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(
                usize::try_from(total).map_err(|_| FaultRuntimeError::CheckpointEncoding)?,
            )
            .map_err(|_| FaultRuntimeError::CheckpointEncoding)?;
        bytes.extend_from_slice(BUNDLE_MAGIC);
        push_length(&mut bytes, manifest.len())?;
        bytes.extend_from_slice(&manifest);
        push_length(&mut bytes, segments.len())?;
        for segment in segments {
            let encoded = self.read_bytes(segment)?;
            decode_resolved_effect_trace_segment(segment, &encoded)?;
            push_length(&mut bytes, encoded.len())?;
            bytes.extend_from_slice(&encoded);
        }
        Ok(bytes)
    }

    /// Returns the exact length of the bundle form without reading segments.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError::CheckpointEncoding`] when the manifest
    /// cannot be encoded.
    pub fn bundle_len(&self) -> Result<u64, FaultRuntimeError> {
        let manifest = self.manifest.canonical_bytes()?;
        Ok(bundle_len(manifest.len(), self.manifest.segments()))
    }

    /// Decodes a bundle, authenticating every segment against the manifest.
    ///
    /// The segments are held in a private in-memory store.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when the bundle exceeds `maximum_bytes`,
    /// is truncated or has trailing bytes, its manifest is invalid, or it
    /// does not carry exactly the referenced segments in order.
    pub fn from_bundle_bytes(
        bytes: &[u8],
        maximum_bytes: usize,
    ) -> Result<Self, FaultRuntimeError> {
        let invalid = |reason: &str| FaultRuntimeError::InvalidTraceSegment {
            segment: String::from("bundle"),
            reason: reason.to_owned(),
        };
        if bytes.len() > maximum_bytes {
            return Err(invalid("bundle exceeds its carrier bound"));
        }
        let mut rest = bytes
            .strip_prefix(BUNDLE_MAGIC)
            .ok_or_else(|| invalid("missing bundle version prefix"))?;
        let manifest_bytes = take_record(&mut rest).ok_or_else(|| invalid("truncated manifest"))?;
        let manifest = ResolvedEffectTraceManifest::from_canonical_bytes(manifest_bytes)?;
        let count = take_length(&mut rest).ok_or_else(|| invalid("truncated segment count"))?;
        if count != manifest.segments().len() {
            return Err(invalid("segment count differs from the manifest"));
        }

        let store = SharedSegmentStore::new();
        for segment in manifest.segments() {
            let encoded = take_record(&mut rest).ok_or_else(|| invalid("truncated segment"))?;
            for item in decode_resolved_effect_trace_segment(segment, encoded)? {
                require_mode_item(manifest.mode(), &item)?;
            }
            store.put_segment(segment.id, encoded).map_err(|error| {
                FaultRuntimeError::TraceStorage {
                    segment: segment.id.encode(),
                    reason: error.to_string(),
                }
            })?;
        }
        if !rest.is_empty() {
            return Err(invalid("trailing bytes after the last segment"));
        }
        Ok(Self::new(manifest, store.into()))
    }

    fn read_bytes(
        &self,
        segment: &ResolvedEffectTraceSegmentRef,
    ) -> Result<Vec<u8>, FaultRuntimeError> {
        self.segments
            .segment(segment.id)
            .map_err(|error| FaultRuntimeError::TraceStorage {
                segment: segment.id.encode(),
                reason: error.to_string(),
            })
    }

    fn load(&self, index: usize) -> Result<Vec<ResolvedReplayWorkItem>, FaultRuntimeError> {
        let segment = self
            .manifest
            .segments()
            .get(index)
            .ok_or(FaultRuntimeError::InvalidReplayTrace)?;
        let items = read_segment(&self.segments, segment)?;
        for item in &items {
            require_mode_item(self.manifest.mode(), item)?;
        }
        Ok(items)
    }
}

/// Streaming iterator over a trace's work items, one segment at a time.
///
/// The iterator yields an error once and then ends.
#[derive(Debug)]
pub struct ResolvedEffectTraceItems<'a> {
    trace: &'a ResolvedEffectTrace,
    segment: usize,
    loaded: std::vec::IntoIter<ResolvedReplayWorkItem>,
    failed: bool,
}

impl Iterator for ResolvedEffectTraceItems<'_> {
    type Item = Result<ResolvedReplayWorkItem, FaultRuntimeError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.failed {
                return None;
            }
            if let Some(item) = self.loaded.next() {
                return Some(Ok(item));
            }
            if self.segment >= self.trace.manifest.segments().len() {
                return None;
            }
            match self.trace.load(self.segment) {
                Ok(items) => {
                    self.loaded = items.into_iter();
                    self.segment += 1;
                }
                Err(error) => {
                    self.failed = true;
                    return Some(Err(error));
                }
            }
        }
    }
}

/// Checkpointed replay position: the trace manifest and the next item.
///
/// The cursor names its segments by identity; restoring it requires the
/// stores that hold them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedEffectReplayCursor {
    /// Manifest of the trace being replayed.
    manifest: ResolvedEffectTraceManifest,
    /// Trace index of the next work item to consume.
    cursor: u64,
}

impl ResolvedEffectReplayCursor {
    /// Returns the replayed trace's manifest.
    #[must_use]
    pub const fn manifest(&self) -> &ResolvedEffectTraceManifest {
        &self.manifest
    }

    /// Returns the trace index of the next work item to consume.
    #[must_use]
    pub const fn cursor(&self) -> u64 {
        self.cursor
    }

    /// Validates the cursor bound and the scenario limits.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] for a cursor beyond the trace or a trace
    /// beyond the scenario's replay counters.
    pub fn validate(&self, resource_limits: FaultResourceLimits) -> Result<(), FaultRuntimeError> {
        self.manifest.admit(resource_limits)?;
        if self.cursor > self.manifest.work_items() {
            return Err(FaultRuntimeError::InvalidReplayTrace);
        }
        Ok(())
    }
}

/// Cursor-driven fault replay over one segmented trace.
///
/// The reader holds at most one decoded segment. [`Self::prepare`] loads the
/// segment holding the cursor before an evaluation inspects it, so
/// [`Self::advance`] after a committed evaluation never performs I/O. Cloning
/// shares the decoded segment and the trace.
#[derive(Clone, Debug)]
pub struct ResolvedEffectTraceReader {
    trace: Arc<ResolvedEffectTrace>,
    cursor: u64,
    loaded: Option<Arc<LoadedSegment>>,
}

#[derive(Debug)]
struct LoadedSegment {
    index: usize,
    first_item: u64,
    items: Vec<ResolvedReplayWorkItem>,
}

impl ResolvedEffectTraceReader {
    /// Starts replaying `trace` from its first work item.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when the trace exceeds the scenario's
    /// replay counters or its first segment cannot be read.
    pub fn new(
        trace: ResolvedEffectTrace,
        resource_limits: FaultResourceLimits,
    ) -> Result<Self, FaultRuntimeError> {
        Self::resume(trace, resource_limits, 0)
    }

    /// Resumes replaying `trace` at a checkpointed cursor.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when the trace exceeds the scenario's
    /// replay counters, the cursor lies beyond the trace, or the segment
    /// holding the cursor cannot be read.
    pub fn resume(
        trace: ResolvedEffectTrace,
        resource_limits: FaultResourceLimits,
        cursor: u64,
    ) -> Result<Self, FaultRuntimeError> {
        trace.manifest.admit(resource_limits)?;
        if cursor > trace.work_items() {
            return Err(FaultRuntimeError::InvalidReplayTrace);
        }
        let mut reader = Self {
            trace: Arc::new(trace),
            cursor,
            loaded: None,
        };
        reader.prepare()?;
        Ok(reader)
    }

    /// Restores a checkpointed cursor against the stores holding its trace.
    ///
    /// # Errors
    ///
    /// Returns the failures of [`Self::resume`].
    pub fn restore(
        cursor: &ResolvedEffectReplayCursor,
        segments: SegmentSources,
        resource_limits: FaultResourceLimits,
    ) -> Result<Self, FaultRuntimeError> {
        Self::resume(
            ResolvedEffectTrace::new(cursor.manifest.clone(), segments),
            resource_limits,
            cursor.cursor,
        )
    }

    /// Returns the checkpointable replay position.
    #[must_use]
    pub fn replay_cursor(&self) -> ResolvedEffectReplayCursor {
        ResolvedEffectReplayCursor {
            manifest: self.trace.manifest.clone(),
            cursor: self.cursor,
        }
    }

    /// Returns the replayed trace.
    #[must_use]
    pub fn trace(&self) -> &ResolvedEffectTrace {
        &self.trace
    }

    /// Returns the replay mode.
    #[must_use]
    pub fn mode(&self) -> FaultReplayMode {
        self.trace.mode()
    }

    /// Returns the trace index of the next work item to consume.
    #[must_use]
    pub const fn cursor(&self) -> u64 {
        self.cursor
    }

    /// Returns the cursor as a diagnostic index.
    #[must_use]
    pub fn cursor_index(&self) -> usize {
        usize::try_from(self.cursor).unwrap_or(usize::MAX)
    }

    /// Loads the segment holding the cursor, when it is not already loaded.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when the segment is absent, fails
    /// authentication, or holds an item invalid for the trace mode.
    pub fn prepare(&mut self) -> Result<(), FaultRuntimeError> {
        if self.cursor >= self.trace.work_items() || self.covers_cursor() {
            return Ok(());
        }
        let segments = self.trace.manifest.segments();
        let index = segments.partition_point(|segment| segment.end_item() <= self.cursor);
        let segment = segments
            .get(index)
            .ok_or(FaultRuntimeError::InvalidReplayTrace)?;
        let items = self.trace.load(index)?;
        self.loaded = Some(Arc::new(LoadedSegment {
            index,
            first_item: segment.first_item,
            items,
        }));
        Ok(())
    }

    /// Returns the work item under the cursor, when it is loaded.
    #[must_use]
    pub fn current(&self) -> Option<&ResolvedReplayWorkItem> {
        let loaded = self.loaded.as_ref()?;
        let offset = self.cursor.checked_sub(loaded.first_item)?;
        loaded.items.get(usize::try_from(offset).ok()?)
    }

    /// Returns the next work item after enforcing its selected alignment.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError::ReplayExhausted`] at the end of the trace,
    /// [`FaultRuntimeError::InvalidReplayTrace`] when the cursor's segment was
    /// not prepared, or [`FaultRuntimeError::ReplayMismatch`] when the next
    /// recorded context does not align with the observed work item.
    pub fn work_item_for_context(
        &self,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
        opportunity: Option<&FaultOpportunity>,
    ) -> Result<Option<&ResolvedReplayWorkItem>, FaultRuntimeError> {
        let mode = self.mode();
        if matches!(mode, FaultReplayMode::OutcomeOnlyNetwork(_))
            && opportunity
                .and_then(FaultOpportunity::network_frame_key)
                .is_none()
        {
            return Ok(None);
        }
        if self.cursor >= self.trace.work_items() {
            return Err(FaultRuntimeError::ReplayExhausted);
        }
        let first = self
            .current()
            .ok_or(FaultRuntimeError::InvalidReplayTrace)?;
        let observed = opportunity.map(FaultOpportunity::id).unwrap_or_default();
        if !aligns(
            mode,
            first,
            coordinate,
            same_coordinate_sequence,
            opportunity,
        )? {
            return Err(FaultRuntimeError::ReplayMismatch {
                index: self.cursor_index(),
                expected: first.opportunity,
                observed,
            });
        }
        Ok(Some(first))
    }

    /// Advances after one fully verified work item.
    ///
    /// The next segment is loaded by the following [`Self::prepare`].
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError::ReplayExhausted`] at the end of the trace.
    pub fn advance(&mut self) -> Result<(), FaultRuntimeError> {
        self.cursor = self
            .cursor
            .checked_add(1)
            .filter(|cursor| *cursor <= self.trace.work_items())
            .ok_or(FaultRuntimeError::ReplayExhausted)?;
        if !self.covers_cursor() {
            self.loaded = None;
        }
        Ok(())
    }

    /// Requires every replay work item to have been consumed.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError::ReplayMismatch`] when work items remain.
    pub fn require_exhausted(&self) -> Result<(), FaultRuntimeError> {
        if self.cursor == self.trace.work_items() {
            Ok(())
        } else {
            Err(FaultRuntimeError::ReplayMismatch {
                index: self.cursor_index(),
                expected: self.current().and_then(|item| item.opportunity),
                observed: ContentHash::default(),
            })
        }
    }

    fn covers_cursor(&self) -> bool {
        self.loaded.as_ref().is_some_and(|loaded| {
            self.cursor >= loaded.first_item
                && self.cursor - loaded.first_item < loaded.items.len() as u64
                && loaded.index < self.trace.manifest.segments().len()
        })
    }
}

fn aligns(
    mode: FaultReplayMode,
    first: &ResolvedReplayWorkItem,
    coordinate: FaultCoordinate,
    same_coordinate_sequence: u64,
    opportunity: Option<&FaultOpportunity>,
) -> Result<bool, FaultRuntimeError> {
    Ok(match mode {
        FaultReplayMode::RecomputedCause | FaultReplayMode::LockedEffect => {
            first.coordinate == coordinate
                && first.same_coordinate_sequence == same_coordinate_sequence
                && first.opportunity == opportunity.map(FaultOpportunity::id)
        }
        FaultReplayMode::OutcomeOnlyNetwork(alignment) => {
            let opportunity = opportunity.ok_or(FaultRuntimeError::InvalidReplayTrace)?;
            let compatible = first.target.as_ref() == Some(opportunity.target())
                && first.operation == Some(opportunity.operation())
                && first.phase == Some(opportunity.phase())
                && first.direction == opportunity.direction();
            compatible
                && match alignment {
                    NetworkOutcomeAlignment::ExactFrameKey => {
                        first.network_frame_key == opportunity.network_frame_key()
                    }
                    NetworkOutcomeAlignment::ProducerDirectionSequence => {
                        first.network_producer_direction_key
                            == opportunity.network_producer_direction_key()
                    }
                    NetworkOutcomeAlignment::ExactEventCoordinate => {
                        first.coordinate == coordinate
                            && first.same_coordinate_sequence == same_coordinate_sequence
                    }
                    NetworkOutcomeAlignment::OrderedTimeBucket { width_nanos } => {
                        if width_nanos == 0 {
                            false
                        } else {
                            let width_ticks =
                                u128::from(width_nanos) * u128::from(SIM_TICKS_PER_NS);
                            u128::from(first.coordinate.virtual_ticks) / width_ticks
                                == u128::from(coordinate.virtual_ticks) / width_ticks
                        }
                    }
                }
        }
    })
}

/// Encodes `items` as one segment starting at `first_item` and stores it.
#[cfg(any(debug_assertions, feature = "test-support"))]
fn store_segment(
    store: &SharedSegmentStore,
    first_item: u64,
    items: &[ResolvedReplayWorkItem],
) -> Result<ResolvedEffectTraceSegmentRef, FaultRuntimeError> {
    let bytes = encode_segment(first_item, items)?;
    let segment = ResolvedEffectTraceSegmentRef {
        id: resolved_effect_trace_segment_id(&bytes),
        first_item,
        item_count: items.len() as u64,
        records: items.iter().map(|item| item.records.len() as u64).sum(),
        encoded_bytes: bytes.len() as u64,
    };
    store
        .put_segment(segment.id, &bytes)
        .map_err(|error| FaultRuntimeError::TraceStorage {
            segment: segment.id.encode(),
            reason: error.to_string(),
        })?;
    Ok(segment)
}

/// Returns the bundle length for a manifest leaf and its referenced segments.
fn bundle_len(manifest_bytes: usize, segments: &[ResolvedEffectTraceSegmentRef]) -> u64 {
    let fixed = BUNDLE_MAGIC.len() as u64 + 8 + manifest_bytes as u64;
    segments
        .iter()
        .map(|segment| 4_u64.saturating_add(segment.encoded_bytes))
        .fold(fixed, u64::saturating_add)
}

fn push_length(bytes: &mut Vec<u8>, length: usize) -> Result<(), FaultRuntimeError> {
    let length = u32::try_from(length).map_err(|_| FaultRuntimeError::CheckpointEncoding)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

fn take_length(rest: &mut &[u8]) -> Option<usize> {
    let (length, tail) = rest.split_first_chunk::<4>()?;
    *rest = tail;
    usize::try_from(u32::from_be_bytes(*length)).ok()
}

fn take_record<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let length = take_length(rest)?;
    let (record, tail) = rest.split_at_checked(length)?;
    *rest = tail;
    Some(record)
}

#[cfg(test)]
#[path = "trace_reader_tests.rs"]
mod tests;
