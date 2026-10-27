//! Lazy, bounded reads of replay-closure frames and the records they hold.
//!
//! A closure's frames live in memory or behind reopenable store handles.
//! [`FrameReader`] fetches one frame at a time, authenticates a stored frame
//! against the digest its root declares, and keeps a small fixed set of
//! decoded frames. Domains and declarations are re-referenced by many
//! entries, so decoded copies are cached by ordinal under a byte budget;
//! opportunities are usually referenced once and are decoded on demand.

use std::collections::{BTreeMap, VecDeque};
use std::ops::Range;
use std::sync::Arc;

use crucible_campaign::{ChoiceDomain, ChoiceOpportunity, SelectableDeclaration};
use crucible_store::content_store::BlobHandle;

use super::format::{
    Entry, FrameSummary, RecordKind, closure_object_id, decode_entry_frame, decode_record_frame,
    invalid,
};
use super::{GuardedCampaignReplayClosure, GuardedCampaignReplayClosureError};

/// Decoded record frames one reader keeps.
///
/// An entry's new records sit in the record frames just before its entry
/// frame, while shared domains sit wherever they were first referenced.
const CACHED_RECORD_FRAMES: usize = 4;

/// Encoded bytes of decoded domains and declarations one reader keeps.
const RECORD_CACHE_BYTES: usize = 64 * 1024 * 1024;

/// Where one frame's bytes live.
#[derive(Clone)]
pub(crate) enum ClosureFrameSource {
    /// Bytes already authenticated against the root.
    Memory(Arc<[u8]>),
    /// A reopenable store object, authenticated on every read.
    Stored(BlobHandle),
}

impl GuardedCampaignReplayClosure {
    /// Returns one frame's bytes, authenticating a stored frame.
    pub(crate) fn frame_bytes(
        &self,
        index: usize,
    ) -> Result<Arc<[u8]>, GuardedCampaignReplayClosureError> {
        let summary = self
            .root
            .frames
            .get(index)
            .ok_or_else(|| invalid("replay closure frame index is out of range"))?;
        match &self.frames[index] {
            ClosureFrameSource::Memory(bytes) => Ok(Arc::clone(bytes)),
            ClosureFrameSource::Stored(handle) => {
                let length = u64::from(summary.length);
                if handle.logical_length() != length {
                    return Err(invalid("stored replay closure frame length differs"));
                }
                let bytes = handle
                    .read_all(length)
                    .map_err(GuardedCampaignReplayClosureError::Store)?;
                if closure_object_id(&bytes) != summary.id() {
                    return Err(invalid("stored replay closure frame digest differs"));
                }
                Ok(bytes.into())
            }
        }
    }
}

/// One decoded record frame.
struct RecordFrame {
    index: usize,
    bytes: Arc<[u8]>,
    first: u64,
    records: Vec<(RecordKind, Range<usize>)>,
}

/// Decoded typed records cached by ordinal under one byte budget.
struct RecordCache<T> {
    records: BTreeMap<u64, Arc<T>>,
    bytes: usize,
}

impl<T> RecordCache<T> {
    fn new() -> Self {
        Self {
            records: BTreeMap::new(),
            bytes: 0,
        }
    }

    fn get(&self, ordinal: u64) -> Option<Arc<T>> {
        self.records.get(&ordinal).cloned()
    }

    fn insert(&mut self, ordinal: u64, encoded_bytes: usize, record: Arc<T>) {
        // Dropping the whole cache keeps the bound without an eviction
        // order; a miss only costs one frame read and decode.
        if self.bytes.saturating_add(encoded_bytes) > RECORD_CACHE_BYTES {
            self.records.clear();
            self.bytes = 0;
        }
        self.records.insert(ordinal, record);
        self.bytes = self.bytes.saturating_add(encoded_bytes);
    }
}

/// Sequential, bounded reader over one closure's entries and records.
pub(super) struct FrameReader<'a> {
    closure: &'a GuardedCampaignReplayClosure,
    entries: Option<(usize, u64, Vec<Entry>)>,
    record_frames: VecDeque<RecordFrame>,
    domains: RecordCache<ChoiceDomain>,
    declarations: RecordCache<SelectableDeclaration>,
}

impl<'a> FrameReader<'a> {
    pub(super) fn new(closure: &'a GuardedCampaignReplayClosure) -> Self {
        Self {
            closure,
            entries: None,
            record_frames: VecDeque::with_capacity(CACHED_RECORD_FRAMES),
            domains: RecordCache::new(),
            declarations: RecordCache::new(),
        }
    }

    /// Returns entry `ordinal`.
    pub(super) fn entry(
        &mut self,
        ordinal: u64,
    ) -> Result<Entry, GuardedCampaignReplayClosureError> {
        let index = self
            .closure
            .root
            .entry_frame(ordinal)
            .ok_or_else(|| invalid("replay closure entry ordinal is out of range"))?;
        if self
            .entries
            .as_ref()
            .is_none_or(|(cached, _, _)| *cached != index)
        {
            let summary = self.closure.root.frames[index];
            let bytes = self.closure.frame_bytes(index)?;
            let entries = decode_entry_frame(&bytes, &summary)?;
            self.entries = Some((index, summary.first, entries));
        }
        let (_, first, entries) = self
            .entries
            .as_ref()
            .ok_or_else(|| invalid("replay closure entry frame is unavailable"))?;
        usize::try_from(ordinal - first)
            .ok()
            .and_then(|offset| entries.get(offset))
            .copied()
            .ok_or_else(|| invalid("replay closure entry ordinal is out of range"))
    }

    /// Returns the canonical bytes of record `ordinal`, which must be `kind`.
    pub(super) fn record_bytes(
        &mut self,
        kind: RecordKind,
        ordinal: u64,
    ) -> Result<(Arc<[u8]>, Range<usize>), GuardedCampaignReplayClosureError> {
        let index = self
            .closure
            .root
            .record_frame(ordinal)
            .ok_or_else(|| invalid("replay closure record ordinal is out of range"))?;
        let position = match self
            .record_frames
            .iter()
            .position(|frame| frame.index == index)
        {
            Some(position) => position,
            None => {
                let summary: FrameSummary = self.closure.root.frames[index];
                let bytes = self.closure.frame_bytes(index)?;
                let records = decode_record_frame(&bytes, &summary)?;
                if self.record_frames.len() == CACHED_RECORD_FRAMES {
                    self.record_frames.pop_front();
                }
                self.record_frames.push_back(RecordFrame {
                    index,
                    bytes,
                    first: summary.first,
                    records,
                });
                self.record_frames.len() - 1
            }
        };

        let frame = &self.record_frames[position];
        let (record_kind, range) = usize::try_from(ordinal - frame.first)
            .ok()
            .and_then(|offset| frame.records.get(offset))
            .ok_or_else(|| invalid("replay closure record ordinal is out of range"))?;
        if *record_kind != kind {
            return Err(invalid("replay closure record has another kind"));
        }
        Ok((Arc::clone(&frame.bytes), range.clone()))
    }

    /// Returns decoded domain `ordinal`.
    pub(super) fn domain(
        &mut self,
        ordinal: u64,
    ) -> Result<Arc<ChoiceDomain>, GuardedCampaignReplayClosureError> {
        if let Some(domain) = self.domains.get(ordinal) {
            return Ok(domain);
        }
        let (bytes, range) = self.record_bytes(RecordKind::Domain, ordinal)?;
        let domain = Arc::new(ChoiceDomain::from_canonical_bytes(&bytes[range.clone()])?);
        self.domains
            .insert(ordinal, range.len(), Arc::clone(&domain));
        Ok(domain)
    }

    /// Returns decoded declaration `ordinal`.
    pub(super) fn declaration(
        &mut self,
        ordinal: u64,
    ) -> Result<Arc<SelectableDeclaration>, GuardedCampaignReplayClosureError> {
        if let Some(declaration) = self.declarations.get(ordinal) {
            return Ok(declaration);
        }
        let (bytes, range) = self.record_bytes(RecordKind::Declaration, ordinal)?;
        let declaration = Arc::new(SelectableDeclaration::from_canonical_bytes(
            &bytes[range.clone()],
        )?);
        self.declarations
            .insert(ordinal, range.len(), Arc::clone(&declaration));
        Ok(declaration)
    }

    /// Returns decoded opportunity `ordinal`.
    pub(super) fn opportunity(
        &mut self,
        ordinal: u64,
    ) -> Result<ChoiceOpportunity, GuardedCampaignReplayClosureError> {
        let (bytes, range) = self.record_bytes(RecordKind::Opportunity, ordinal)?;
        Ok(ChoiceOpportunity::from_canonical_bytes(&bytes[range])?)
    }
}
