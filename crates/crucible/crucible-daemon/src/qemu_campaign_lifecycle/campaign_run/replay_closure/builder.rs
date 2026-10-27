//! The one canonical encoder of version 2 replay-closure frames.
//!
//! [`ClosureBuilder`] numbers records by first reference, packs them
//! greedily into record frames, and closes the open record frame before
//! every entry frame. Construction retains the frames it emits; validation
//! re-encodes a decoded closure in digest-only mode and compares roots, which
//! proves canonical record order, deduplication, and frame packing at once.
//! A digest-only builder holds at most one open frame of each kind plus one
//! identity digest per distinct record, a small fraction of the schedule the
//! closure covers.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::GuardedCampaignReplayClosureError;
use super::format::{
    ClosureRoot, Entry, FRAME_HEADER_BYTES, FrameKind, MAX_FRAME_ITEMS,
    MAX_REPLAY_CLOSURE_FRAME_BYTES, MAX_REPLAY_CLOSURE_FRAMES, RECORD_HEADER_BYTES, RecordKind,
    append_record, closure_object_id, encode_entry_frame, frame_header, invalid, set_frame_count,
};

/// A finished closure's root and, when retained, its frames in order.
pub(super) type ClosureParts = (ClosureRoot, Vec<Arc<[u8]>>);

/// Whether a builder keeps the frames it emits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FrameRetention {
    /// Keep every frame, to construct a closure.
    Retain,
    /// Keep only frame digests, to prove a decoded closure canonical.
    DigestOnly,
}

/// Incremental encoder of one closure's frames and root.
pub(super) struct ClosureBuilder {
    retention: FrameRetention,
    /// Ordinal of every record so far, by kind and record identity digest.
    ordinals: BTreeMap<(RecordKind, [u8; 32]), u64>,
    next_record: u64,
    entries: Vec<Entry>,
    record_frame: Vec<u8>,
    record_items: usize,
    table: Vec<(FrameKind, u32, u32, [u8; 32])>,
    frames: Vec<Arc<[u8]>>,
}

impl ClosureBuilder {
    pub(super) fn new(retention: FrameRetention) -> Self {
        Self {
            retention,
            ordinals: BTreeMap::new(),
            next_record: 0,
            entries: Vec::new(),
            record_frame: Vec::new(),
            record_items: 0,
            table: Vec::new(),
            frames: Vec::new(),
        }
    }

    /// Returns the ordinal the next new record will take.
    pub(super) const fn next_record(&self) -> u64 {
        self.next_record
    }

    /// Returns the ordinal of a record, appending it when it is new.
    ///
    /// `encode` runs only for a new record, so a re-referenced domain is
    /// neither encoded nor hashed again.
    pub(super) fn record(
        &mut self,
        kind: RecordKind,
        id: [u8; 32],
        encode: impl FnOnce() -> Vec<u8>,
    ) -> Result<u64, GuardedCampaignReplayClosureError> {
        if let Some(ordinal) = self.ordinals.get(&(kind, id)) {
            return Ok(*ordinal);
        }
        self.append_new(kind, id, &encode())
    }

    /// Appends a record that must not have been referenced before.
    ///
    /// # Errors
    ///
    /// Returns an error when the record repeats an earlier one, cannot fit
    /// one frame, or the closure exceeds its frame bound.
    pub(super) fn append_new(
        &mut self,
        kind: RecordKind,
        id: [u8; 32],
        record: &[u8],
    ) -> Result<u64, GuardedCampaignReplayClosureError> {
        if self.ordinals.contains_key(&(kind, id)) {
            return Err(invalid("replay closure repeats a choice record"));
        }
        let item = RECORD_HEADER_BYTES + record.len();
        if FRAME_HEADER_BYTES + item > MAX_REPLAY_CLOSURE_FRAME_BYTES {
            return Err(invalid("replay closure record exceeds the frame bound"));
        }

        if self.record_items == MAX_FRAME_ITEMS
            || self.record_frame.len() + item > MAX_REPLAY_CLOSURE_FRAME_BYTES
        {
            self.close_record_frame()?;
        }
        if self.record_frame.is_empty() {
            self.record_frame = frame_header(FrameKind::Records, 0, item);
        }
        append_record(&mut self.record_frame, kind, record);
        self.record_items += 1;

        let ordinal = self.next_record;
        self.ordinals.insert((kind, id), ordinal);
        self.next_record += 1;
        Ok(ordinal)
    }

    /// Appends one entry whose records were all referenced already.
    pub(super) fn entry(&mut self, entry: Entry) -> Result<(), GuardedCampaignReplayClosureError> {
        self.entries.push(entry);
        if self.entries.len() == MAX_FRAME_ITEMS {
            self.flush_entries()?;
        }
        Ok(())
    }

    /// Closes the open frames and encodes the root.
    ///
    /// Returns the root and, when retaining, every frame in order.
    pub(super) fn finish(mut self) -> Result<ClosureParts, GuardedCampaignReplayClosureError> {
        if !self.entries.is_empty() {
            self.flush_entries()?;
        }
        if self.record_items != 0 {
            return Err(invalid("replay closure has records without an entry"));
        }
        let root = ClosureRoot::encode(&self.table)?;
        Ok((root, self.frames))
    }

    fn flush_entries(&mut self) -> Result<(), GuardedCampaignReplayClosureError> {
        self.close_record_frame()?;
        let frame = encode_entry_frame(&self.entries);
        let count = self.entries.len();
        self.entries.clear();
        self.push_frame(FrameKind::Entries, count, frame)
    }

    fn close_record_frame(&mut self) -> Result<(), GuardedCampaignReplayClosureError> {
        if self.record_items == 0 {
            return Ok(());
        }
        let count = std::mem::take(&mut self.record_items);
        let mut frame = std::mem::take(&mut self.record_frame);
        set_frame_count(&mut frame, count);
        self.push_frame(FrameKind::Records, count, frame)
    }

    fn push_frame(
        &mut self,
        kind: FrameKind,
        count: usize,
        frame: Vec<u8>,
    ) -> Result<(), GuardedCampaignReplayClosureError> {
        if self.table.len() == MAX_REPLAY_CLOSURE_FRAMES {
            return Err(invalid("replay closure exceeds its frame bound"));
        }
        // Frames hold at most MAX_FRAME_ITEMS items and MAX_REPLAY_CLOSURE_FRAME_BYTES
        // bytes, so both fit u32.
        self.table.push((
            kind,
            count as u32,
            frame.len() as u32,
            closure_object_id(&frame).digest(),
        ));
        if self.retention == FrameRetention::Retain {
            self.frames.push(frame.into());
        }
        Ok(())
    }
}
