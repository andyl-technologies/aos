//! Append-only resolved-effect trace writer: sealed segments plus an open tail.
//!
//! [`ResolvedEffectTraceWriter`] is the recording side of the segmented trace.
//! Finalized work items accumulate in an open tail. Before an append would
//! make the tail's encoding exceed [`SEGMENT_TARGET_BYTES`], the tail is sealed
//! into one content-addressed segment, written to the writer's
//! [`SegmentSink`], and dropped from memory; only its reference stays.
//!
//! Seal points depend only on the appended item sequence. A checkpoint
//! therefore never seals: [`ResolvedEffectTracePosition`] carries the sealed
//! references, the chain, the running counters, and the open tail, so a
//! continuation restored from a checkpoint seals exactly where an
//! uninterrupted execution would, and the published trace is identical whether
//! or not the world was retained (RFC-0020 CCOMP-21 and CCOMP-26).
//!
//! The running counters make the `thin_replay_events` and
//! `resolved_effect_records` limits O(1) per append (RFC-0014 section 13.7).

use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::trace_format::{empty_chain, encode_segment, encoded_item_len, extend_chain};
use super::*;
use crate::segment_store::{
    MAX_MANIFEST_SEGMENTS, SEGMENT_TARGET_BYTES, SegmentSink, SegmentSource, SegmentSources,
};

/// The digest with the longest CBOR encoding.
///
/// A [`ContentHash`] encodes as 32 CBOR integers, each one or two bytes wide,
/// so a measurement that substitutes this digest for an unknown one is an
/// upper bound on the eventual encoding.
pub(crate) const WIDEST_CONTENT_HASH: ContentHash = ContentHash {
    bytes: [u8::MAX; 32],
};

/// Checkpointable position of a resolved-effect trace writer.
///
/// The position is bounded independently of the trace length: at most
/// [`MAX_MANIFEST_SEGMENTS`] segment references and an open tail whose
/// encoding stays within [`SEGMENT_TARGET_BYTES`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedEffectTracePosition {
    /// References of every sealed segment, in trace order.
    #[serde(deserialize_with = "super::super::fallible_decode::deserialize_vec")]
    sealed: Vec<ResolvedEffectTraceSegmentRef>,
    /// Chain hash after the last sealed segment.
    chain: ContentHash,
    /// Work items appended so far, sealed and open.
    work_items: u64,
    /// Resolved-effect records across every appended work item.
    records: u64,
    /// Finalized work items not yet sealed.
    #[serde(deserialize_with = "super::super::fallible_decode::deserialize_vec")]
    tail: Vec<ResolvedReplayWorkItem>,
}

impl ResolvedEffectTracePosition {
    /// Returns the position of an empty trace.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            sealed: Vec::new(),
            chain: empty_chain(),
            work_items: 0,
            records: 0,
            tail: Vec::new(),
        }
    }

    /// Returns the number of appended work items.
    #[must_use]
    pub const fn work_items(&self) -> u64 {
        self.work_items
    }

    /// Returns the number of appended resolved-effect records.
    #[must_use]
    pub const fn records(&self) -> u64 {
        self.records
    }

    /// Returns the chain hash after the last sealed segment.
    #[must_use]
    pub const fn chain(&self) -> ContentHash {
        self.chain
    }

    /// Returns the sealed segment references, in trace order.
    #[must_use]
    pub fn sealed(&self) -> &[ResolvedEffectTraceSegmentRef] {
        &self.sealed
    }

    /// Returns the work items not yet sealed.
    #[must_use]
    pub fn tail(&self) -> &[ResolvedReplayWorkItem] {
        &self.tail
    }

    /// Returns the most recently appended work item, when it is still open.
    #[must_use]
    pub fn last_open(&self) -> Option<&ResolvedReplayWorkItem> {
        self.tail.last()
    }

    /// Validates the position's structure, counters, and scenario limits.
    ///
    /// Sealed segments are authenticated when they are read, not here.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when the sealed references are not a
    /// dense chain, the counters disagree with the references and tail, a
    /// tail item is invalid, or a counter exceeds its scenario limit.
    pub fn validate(&self, resource_limits: FaultResourceLimits) -> Result<(), FaultRuntimeError> {
        let sealed = ResolvedEffectTraceManifest::new(
            FaultReplayMode::RecomputedCause,
            self.sealed.clone(),
        )?;
        if sealed.chain() != self.chain {
            return Err(FaultRuntimeError::InvalidReplayTrace);
        }
        let mut work_items = sealed.work_items();
        let mut records = sealed.records();
        for item in &self.tail {
            item.validate()?;
            work_items = work_items
                .checked_add(1)
                .ok_or(FaultRuntimeError::CountOverflow("thin_replay_events"))?;
            records = records
                .checked_add(item.records.len() as u64)
                .ok_or(FaultRuntimeError::CountOverflow("resolved_effect_records"))?;
        }
        if work_items != self.work_items || records != self.records {
            return Err(FaultRuntimeError::InvalidReplayTrace);
        }
        resource_limits
            .reserve("thin_replay_events", 0, self.work_items)
            .map_err(FaultRuntimeError::ResourceLimit)?;
        resource_limits
            .reserve("resolved_effect_records", 0, self.records)
            .map_err(FaultRuntimeError::ResourceLimit)
    }

    /// Appends an open item without validation or limit checks, so tests can
    /// build hostile checkpoints whose counters agree with their contents.
    #[cfg(test)]
    pub(crate) fn push_tail_unchecked(&mut self, item: ResolvedReplayWorkItem) {
        self.work_items += 1;
        self.records += item.records.len() as u64;
        self.tail.push(item);
    }

    /// Returns the open items for in-place test mutation.
    #[cfg(test)]
    pub(crate) fn tail_mut(&mut self) -> &mut [ResolvedReplayWorkItem] {
        &mut self.tail
    }

    /// Returns the trace index of the first open work item.
    fn tail_first_item(&self) -> u64 {
        self.work_items.saturating_sub(self.tail.len() as u64)
    }
}

/// Recording writer of one segmented resolved-effect trace.
///
/// Cloning shares the segment sink and copies the bounded position.
#[derive(Clone)]
pub struct ResolvedEffectTraceWriter {
    sink: Arc<dyn SegmentSink>,
    resource_limits: FaultResourceLimits,
    position: ResolvedEffectTracePosition,
    tail_bytes: usize,
    tail_records: u64,
}

impl ResolvedEffectTraceWriter {
    /// Starts an empty trace that seals into `sink`.
    #[must_use]
    pub fn new(sink: Arc<dyn SegmentSink>, resource_limits: FaultResourceLimits) -> Self {
        Self {
            sink,
            resource_limits,
            position: ResolvedEffectTracePosition::empty(),
            tail_bytes: 0,
            tail_records: 0,
        }
    }

    /// Continues a trace from a checkpointed position.
    ///
    /// The sealed segments the position references must be readable from
    /// `sink` when the trace is later exported.
    ///
    /// # Errors
    ///
    /// Returns the validation failures of
    /// [`ResolvedEffectTracePosition::validate`], or
    /// [`FaultRuntimeError::TraceItemTooLarge`] for an oversized tail item.
    pub fn restore(
        sink: Arc<dyn SegmentSink>,
        resource_limits: FaultResourceLimits,
        position: ResolvedEffectTracePosition,
    ) -> Result<Self, FaultRuntimeError> {
        position.validate(resource_limits)?;
        let mut tail_bytes = 0_usize;
        let mut tail_records = 0_u64;
        for item in &position.tail {
            tail_bytes = tail_bytes.saturating_add(admit_item_len(item)?);
            tail_records = tail_records.saturating_add(item.records.len() as u64);
        }
        if tail_bytes > SEGMENT_TARGET_BYTES {
            return Err(FaultRuntimeError::InvalidReplayTrace);
        }
        Ok(Self {
            sink,
            resource_limits,
            position,
            tail_bytes,
            tail_records,
        })
    }

    /// Returns the checkpointable position.
    #[must_use]
    pub const fn position(&self) -> &ResolvedEffectTracePosition {
        &self.position
    }

    /// Returns the number of appended work items.
    #[must_use]
    pub const fn work_items(&self) -> u64 {
        self.position.work_items
    }

    /// Returns the number of appended resolved-effect records.
    #[must_use]
    pub const fn records(&self) -> u64 {
        self.position.records
    }

    /// Returns the encoded bytes of the open tail's items.
    #[must_use]
    pub const fn tail_bytes(&self) -> usize {
        self.tail_bytes
    }

    /// Returns the scenario limits applied to appends.
    #[must_use]
    pub const fn resource_limits(&self) -> FaultResourceLimits {
        self.resource_limits
    }

    /// Returns the sink that receives sealed segments.
    #[must_use]
    pub const fn sink(&self) -> &Arc<dyn SegmentSink> {
        &self.sink
    }

    /// Requires room for one more work item carrying `records` records.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError::ResourceLimit`] when the append would
    /// exceed `thin_replay_events` or `resolved_effect_records`.
    pub fn reserve(&self, records: u64) -> Result<(), FaultRuntimeError> {
        self.resource_limits
            .reserve("thin_replay_events", self.position.work_items, 1)
            .map_err(FaultRuntimeError::ResourceLimit)?;
        self.resource_limits
            .reserve("resolved_effect_records", self.position.records, records)
            .map_err(FaultRuntimeError::ResourceLimit)
    }

    /// Appends one finalized work item, sealing the tail first when full.
    ///
    /// A refused append leaves every previously appended item retained.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] for an invalid item, an item beyond
    /// [`MAX_RESOLVED_EFFECT_TRACE_ITEM_BYTES`], an append beyond a scenario
    /// counter, or a tail that cannot be sealed into the sink.
    pub fn append(&mut self, item: ResolvedReplayWorkItem) -> Result<(), FaultRuntimeError> {
        item.validate()?;
        let item_records = item.records.len() as u64;
        self.reserve(item_records)?;
        let bytes = admit_item_len(&item)?;
        if !self.position.tail.is_empty()
            && self.tail_bytes.saturating_add(bytes) > SEGMENT_TARGET_BYTES
        {
            self.seal()?;
        }

        self.position.tail.push(item);
        self.position.work_items += 1;
        self.position.records += item_records;
        self.tail_bytes += bytes;
        self.tail_records += item_records;
        Ok(())
    }

    /// Seals the open tail, if any, into one stored segment.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError::TraceSegmentLimit`] when the trace already
    /// references [`MAX_MANIFEST_SEGMENTS`] segments, or the segment's
    /// encoding or storage failure. The tail is retained on error.
    fn seal(&mut self) -> Result<(), FaultRuntimeError> {
        let Some(segment) = self.store_tail()? else {
            return Ok(());
        };
        self.position.chain = extend_chain(self.position.chain, &segment);
        self.position.sealed.push(segment);
        self.position.tail.clear();
        self.tail_bytes = 0;
        self.tail_records = 0;
        Ok(())
    }

    /// Encodes and stores the open tail without changing the position.
    fn store_tail(&self) -> Result<Option<ResolvedEffectTraceSegmentRef>, FaultRuntimeError> {
        if self.position.tail.is_empty() {
            return Ok(None);
        }
        if self.position.sealed.len() >= MAX_MANIFEST_SEGMENTS {
            return Err(FaultRuntimeError::TraceSegmentLimit {
                limit: MAX_MANIFEST_SEGMENTS,
            });
        }
        let first_item = self.position.tail_first_item();
        let bytes = encode_segment(first_item, &self.position.tail)?;
        let id = resolved_effect_trace_segment_id(&bytes);
        self.sink
            .put_segment(id, &bytes)
            .map_err(|error| FaultRuntimeError::TraceStorage {
                segment: id.encode(),
                reason: error.to_string(),
            })?;
        Ok(Some(ResolvedEffectTraceSegmentRef {
            id,
            first_item,
            item_count: self.position.tail.len() as u64,
            records: self.tail_records,
            encoded_bytes: bytes.len() as u64,
        }))
    }

    /// Returns the complete trace so far without changing the writer.
    ///
    /// The open tail is stored as the final segment, exactly as a seal at the
    /// stop would store it, so exporting mid-execution never moves a later
    /// seal point.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when the tail cannot be stored or the
    /// manifest is invalid for `mode`.
    pub fn export(&self, mode: FaultReplayMode) -> Result<ResolvedEffectTrace, FaultRuntimeError> {
        let mut segments = self.position.sealed.clone();
        segments.extend(self.store_tail()?);
        let manifest = ResolvedEffectTraceManifest::new(mode, segments)?;
        Ok(ResolvedEffectTrace::new(
            manifest,
            SegmentSources::single(Arc::new(SinkSource(Arc::clone(&self.sink)))),
        ))
    }

    /// Seals the tail and returns the finished trace.
    ///
    /// # Errors
    ///
    /// Returns the failures of [`Self::export`].
    pub fn finish(self, mode: FaultReplayMode) -> Result<ResolvedEffectTrace, FaultRuntimeError> {
        self.export(mode)
    }

    /// Visits every appended work item in order, one sealed segment at a time.
    ///
    /// # Errors
    ///
    /// Returns an error converted from [`FaultRuntimeError`] when a sealed
    /// segment is missing or fails authentication, or the first error `visit`
    /// returns.
    pub fn try_for_each_item<E: From<FaultRuntimeError>>(
        &self,
        mut visit: impl FnMut(&ResolvedReplayWorkItem) -> Result<(), E>,
    ) -> Result<(), E> {
        for segment in &self.position.sealed {
            for item in read_segment(self.sink.as_ref(), segment)? {
                visit(&item)?;
            }
        }
        for item in &self.position.tail {
            visit(item)?;
        }
        Ok(())
    }

    /// Measures the checkpointed position after appending one item.
    ///
    /// The open tail is never re-encoded: its length is tracked as items are
    /// appended, and CBOR array encoding is a header followed by the items.
    /// Without a seal the measurement is exact; with one, the unknown chain
    /// digest is measured at its widest encoding, so the result is an upper
    /// bound at most 32 bytes above the eventual length.
    /// The returned shell is the position after the append with an empty
    /// tail; [`TraceCapacityShell::encoded_len`] adds the tail back to the
    /// measured length of any structure that embeds the shell.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError::CheckpointEncoding`] when the sealed
    /// segment a seal would produce cannot be measured.
    pub(crate) fn capacity_shell(
        &self,
        item_bytes: usize,
        item_records: u64,
    ) -> Result<TraceCapacityShell, FaultRuntimeError> {
        let seals = !self.position.tail.is_empty()
            && self.tail_bytes.saturating_add(item_bytes) > SEGMENT_TARGET_BYTES;
        let mut sealed = self.position.sealed.clone();
        let (tail_items, tail_bytes) = if seals {
            let first_item = self.position.tail_first_item();
            let encoded_bytes = segment_len(self.position.tail.len(), self.tail_bytes, first_item)?;
            sealed.push(ResolvedEffectTraceSegmentRef {
                // Every segment identity encodes to the same length, so a
                // placeholder digest measures exactly.
                id: resolved_effect_trace_segment_id(&[]),
                first_item,
                item_count: self.position.tail.len() as u64,
                records: self.tail_records,
                encoded_bytes: encoded_bytes as u64,
            });
            (1_usize, item_bytes)
        } else {
            (
                self.position.tail.len().saturating_add(1),
                self.tail_bytes.saturating_add(item_bytes),
            )
        };
        // A seal changes the chain to a digest not known until the segment is
        // encoded; the widest digest keeps the measurement an upper bound.
        let chain = if seals {
            WIDEST_CONTENT_HASH
        } else {
            self.position.chain
        };
        Ok(TraceCapacityShell {
            position: ResolvedEffectTracePosition {
                sealed,
                chain,
                work_items: self.position.work_items.saturating_add(1),
                records: self.position.records.saturating_add(item_records),
                tail: Vec::new(),
            },
            tail_items,
            tail_bytes,
        })
    }
}

/// A position measured without re-encoding its open tail.
#[derive(Debug)]
pub(crate) struct TraceCapacityShell {
    /// The measured position with an empty tail.
    pub(crate) position: ResolvedEffectTracePosition,
    tail_items: usize,
    tail_bytes: usize,
}

impl TraceCapacityShell {
    /// Returns the encoded length of a structure that embeds the shell once,
    /// given that structure's measured length with the shell's empty tail.
    pub(crate) fn encoded_len(&self, measured_with_empty_tail: u64) -> u64 {
        measured_with_empty_tail
            .saturating_sub(cbor_header_len(0) as u64)
            .saturating_add(cbor_header_len(self.tail_items as u64) as u64)
            .saturating_add(self.tail_bytes as u64)
    }
}

impl fmt::Debug for ResolvedEffectTraceWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedEffectTraceWriter")
            .field("position", &self.position)
            .field("tail_bytes", &self.tail_bytes)
            .finish_non_exhaustive()
    }
}

/// Read access to a writer's sink through the shared source trait.
struct SinkSource(Arc<dyn SegmentSink>);

impl SegmentSource for SinkSource {
    fn segment(&self, id: crucible_store::content_store::ContentId) -> std::io::Result<Vec<u8>> {
        self.0.segment(id)
    }
}

/// Reads one segment from `source` and authenticates it.
pub(super) fn read_segment(
    source: &(impl SegmentSource + ?Sized),
    segment: &ResolvedEffectTraceSegmentRef,
) -> Result<Vec<ResolvedReplayWorkItem>, FaultRuntimeError> {
    let bytes = source
        .segment(segment.id)
        .map_err(|error| FaultRuntimeError::TraceStorage {
            segment: segment.id.encode(),
            reason: error.to_string(),
        })?;
    decode_resolved_effect_trace_segment(segment, &bytes)
}

/// Measures one item, refusing an item no segment may hold.
fn admit_item_len(item: &ResolvedReplayWorkItem) -> Result<usize, FaultRuntimeError> {
    let bytes = encoded_item_len(item)?;
    if bytes > MAX_RESOLVED_EFFECT_TRACE_ITEM_BYTES {
        return Err(FaultRuntimeError::TraceItemTooLarge {
            bytes: bytes as u64,
        });
    }
    Ok(bytes)
}

/// Returns the encoded length of a segment holding `items` items whose
/// encodings total `items_bytes`.
fn segment_len(
    items: usize,
    items_bytes: usize,
    first_item: u64,
) -> Result<usize, FaultRuntimeError> {
    let empty = encode_segment(first_item, &[])?.len();
    Ok(empty
        .saturating_sub(cbor_header_len(0))
        .saturating_add(cbor_header_len(items as u64))
        .saturating_add(items_bytes))
}

/// Returns the length of a CBOR major-type header carrying `argument`.
pub(super) const fn cbor_header_len(argument: u64) -> usize {
    if argument < 24 {
        1
    } else if argument <= u8::MAX as u64 {
        2
    } else if argument <= u16::MAX as u64 {
        3
    } else if argument <= u32::MAX as u64 {
        5
    } else {
        9
    }
}

#[cfg(test)]
#[path = "trace_log_tests.rs"]
mod tests;
