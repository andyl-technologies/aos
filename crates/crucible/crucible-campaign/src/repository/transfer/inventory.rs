//! Streamed archive inventories, closure spills, and bounded reachability.
//!
//! Archive planning and inspection never hold a complete inventory or source
//! closure in memory. Closure identities are external-sorted into the
//! repository's private scratch storage, inventory entries are replayed one
//! canonical page at a time, and policy reachability is computed by repeated
//! sort-merge joins over a spilled edge list. Records order like
//! [`ContentId`], so every comparison between a closure, an inventory, and a
//! reachable set is a forward merge:
//!
//! ```text
//! closure record (38 bytes): ordered id record || exact_leaf:u8
//! edge record (74 bytes):    ordered parent id record || ordered child id record
//! ```
//!
//! None of these records is a published format; the canonical inventory pages
//! and manifest digests are unchanged.

use std::cmp::Ordering;
use std::io;
use std::mem;
use std::sync::Arc;

use super::*;
use crate::archive::{InventoryDigest, InventoryLength, InventorySummary};
use crate::spill::{
    ExternalSorter, FrameReader, FrameWriter, ID_RECORD_BYTES, IdRecord, RUN_RECORDS, RecordReader,
    SpillFile, SpillStorage, SpillWriter, decode_ordered_id_record, ordered_id_record,
};

/// Width of one closure record: an ordered identity and its exact-leaf flag.
const CLOSURE_RECORD_BYTES: usize = ID_RECORD_BYTES + 1;

/// Width of one edge record: ordered parent identity, then ordered child identity.
const EDGE_RECORD_BYTES: usize = 2 * ID_RECORD_BYTES;

/// Maps a scratch-storage failure into the repository error vocabulary.
pub(super) fn scratch(
    operation: &'static str,
) -> impl FnOnce(io::Error) -> CampaignRepositoryError {
    move |source| CampaignRepositoryError::Scratch { operation, source }
}

/// Sorted, deduplicated union of the closures an archive represents.
///
/// An identity reached by several walks keeps one record per exact-leaf flag;
/// [`ClosureCursor`] folds them into one identity that is exact when any walk
/// reached it as an exact raw leaf.
pub(super) struct ClosureSpill {
    sorter: ExternalSorter<CLOSURE_RECORD_BYTES>,
}

impl ClosureSpill {
    pub(super) fn new(storage: &SpillStorage) -> Self {
        Self {
            sorter: ExternalSorter::new(storage, "archive-closure", RUN_RECORDS),
        }
    }

    pub(super) fn push(
        &mut self,
        id: ContentId,
        exact_leaf: bool,
    ) -> Result<(), CampaignRepositoryError> {
        let mut record = [0_u8; CLOSURE_RECORD_BYTES];
        record[..ID_RECORD_BYTES].copy_from_slice(&ordered_id_record(id));
        record[ID_RECORD_BYTES] = u8::from(exact_leaf);
        self.sorter
            .push(record)
            .map_err(scratch("spill-archive-closure"))
    }

    pub(super) fn finish(self) -> Result<SpillFile, CampaignRepositoryError> {
        self.sorter
            .finish()
            .map_err(scratch("sort-archive-closure"))
    }
}

/// Ascending replay of distinct identities from a finished [`ClosureSpill`].
pub(super) struct ClosureCursor {
    reader: RecordReader<CLOSURE_RECORD_BYTES>,
    head: Option<[u8; CLOSURE_RECORD_BYTES]>,
}

impl ClosureCursor {
    pub(super) fn open(file: &SpillFile) -> Result<Self, CampaignRepositoryError> {
        let mut reader = file
            .reader::<CLOSURE_RECORD_BYTES>()
            .map_err(scratch("open-archive-closure"))?;
        let head = reader
            .next_record()
            .map_err(scratch("read-archive-closure"))?;
        Ok(Self { reader, head })
    }

    /// Returns the next identity and whether any walk reached it as an exact leaf.
    pub(super) fn next(&mut self) -> Result<Option<(ContentId, bool)>, CampaignRepositoryError> {
        let Some(first) = self.head.take() else {
            return Ok(None);
        };
        let mut exact_leaf = first[ID_RECORD_BYTES] != 0;
        self.head = self.advance()?;
        while let Some(next) = self.head
            && next[..ID_RECORD_BYTES] == first[..ID_RECORD_BYTES]
        {
            exact_leaf |= next[ID_RECORD_BYTES] != 0;
            self.head = self.advance()?;
        }
        let id = decode_ordered_id_record(&first[..ID_RECORD_BYTES])
            .map_err(scratch("decode-archive-closure"))?;
        Ok(Some((id, exact_leaf)))
    }

    fn advance(&mut self) -> Result<Option<[u8; CLOSURE_RECORD_BYTES]>, CampaignRepositoryError> {
        self.reader
            .next_record()
            .map_err(scratch("read-archive-closure"))
    }
}

/// Spilled parent-to-child edges of the objects an archive authenticates.
pub(super) struct EdgeSpill {
    sorter: ExternalSorter<EDGE_RECORD_BYTES>,
}

impl EdgeSpill {
    pub(super) fn new(storage: &SpillStorage) -> Self {
        Self {
            sorter: ExternalSorter::new(storage, "archive-edges", RUN_RECORDS),
        }
    }

    pub(super) fn push(
        &mut self,
        parent: ContentId,
        child: ContentId,
    ) -> Result<(), CampaignRepositoryError> {
        let mut record = [0_u8; EDGE_RECORD_BYTES];
        record[..ID_RECORD_BYTES].copy_from_slice(&ordered_id_record(parent));
        record[ID_RECORD_BYTES..].copy_from_slice(&ordered_id_record(child));
        self.sorter
            .push(record)
            .map_err(scratch("spill-archive-edges"))
    }

    pub(super) fn finish(self) -> Result<SpillFile, CampaignRepositoryError> {
        self.sorter.finish().map_err(scratch("sort-archive-edges"))
    }
}

/// Returns the sorted identities reachable from `root` along `edges`, root included.
///
/// Each round joins the current frontier with the parent-sorted edges and
/// keeps only children not yet visited, so a round's memory is one sorter run
/// and the number of rounds is the depth of the reachable graph rather than
/// its size. Every round rereads the edge spill.
pub(super) fn reachable_from(
    storage: &SpillStorage,
    root: ContentId,
    edges: &SpillFile,
) -> Result<SpillFile, CampaignRepositoryError> {
    reachable_records(storage, root, edges).map_err(scratch("compute-archive-reachability"))
}

fn reachable_records(
    storage: &SpillStorage,
    root: ContentId,
    edges: &SpillFile,
) -> io::Result<SpillFile> {
    let mut visited = single_id_run(storage, root)?;
    let mut frontier = single_id_run(storage, root)?;
    while frontier.records() != 0 {
        let candidates = expand_frontier(storage, &frontier, edges)?;
        (visited, frontier) = absorb_candidates(storage, &visited, &candidates)?;
    }
    Ok(visited)
}

fn single_id_run(storage: &SpillStorage, id: ContentId) -> io::Result<SpillFile> {
    let mut writer = SpillWriter::<ID_RECORD_BYTES>::create(storage, "archive-reach-root")?;
    writer.push(&ordered_id_record(id))?;
    writer.finish()
}

/// Collects the children of every frontier identity, sorted and deduplicated.
fn expand_frontier(
    storage: &SpillStorage,
    frontier: &SpillFile,
    edges: &SpillFile,
) -> io::Result<SpillFile> {
    let mut children =
        ExternalSorter::<ID_RECORD_BYTES>::new(storage, "archive-reach-children", RUN_RECORDS);
    let mut parents = frontier.reader::<ID_RECORD_BYTES>()?;
    let mut edge_reader = edges.reader::<EDGE_RECORD_BYTES>()?;
    let mut parent = parents.next_record()?;
    let mut edge = edge_reader.next_record()?;
    while let (Some(parent_id), Some(edge_record)) = (parent, edge) {
        match edge_record[..ID_RECORD_BYTES].cmp(&parent_id[..]) {
            Ordering::Less => edge = edge_reader.next_record()?,
            Ordering::Greater => parent = parents.next_record()?,
            Ordering::Equal => {
                let mut child: IdRecord = [0_u8; ID_RECORD_BYTES];
                child.copy_from_slice(&edge_record[ID_RECORD_BYTES..]);
                children.push(child)?;
                edge = edge_reader.next_record()?;
            }
        }
    }
    children.finish()
}

/// Merges candidates into the visited set and returns it with the unvisited candidates.
fn absorb_candidates(
    storage: &SpillStorage,
    visited: &SpillFile,
    candidates: &SpillFile,
) -> io::Result<(SpillFile, SpillFile)> {
    let mut union = SpillWriter::<ID_RECORD_BYTES>::create(storage, "archive-reach-visited")?;
    let mut fresh = SpillWriter::<ID_RECORD_BYTES>::create(storage, "archive-reach-frontier")?;
    let mut known = visited.reader::<ID_RECORD_BYTES>()?;
    let mut offered = candidates.reader::<ID_RECORD_BYTES>()?;
    let mut old = known.next_record()?;
    let mut new = offered.next_record()?;
    loop {
        match (old, new) {
            (None, None) => break,
            (Some(old_id), Some(new_id)) if old_id == new_id => {
                union.push(&old_id)?;
                old = known.next_record()?;
                new = offered.next_record()?;
            }
            (Some(old_id), Some(new_id)) if old_id < new_id => {
                union.push(&old_id)?;
                old = known.next_record()?;
            }
            (Some(old_id), None) => {
                union.push(&old_id)?;
                old = known.next_record()?;
            }
            // Either the visited set is exhausted or the candidate sorts first:
            // it has not been visited.
            (_, Some(new_id)) => {
                union.push(&new_id)?;
                fresh.push(&new_id)?;
                new = offered.next_record()?;
            }
        }
    }
    Ok((union.finish()?, fresh.finish()?))
}

/// Forward-only membership in a sorted identity spill such as a reachable set.
pub(super) struct IdMembership {
    reader: RecordReader<ID_RECORD_BYTES>,
    head: Option<IdRecord>,
}

impl IdMembership {
    pub(super) fn open(file: &SpillFile) -> Result<Self, CampaignRepositoryError> {
        let mut reader = file
            .reader::<ID_RECORD_BYTES>()
            .map_err(scratch("open-archive-identity-set"))?;
        let head = reader
            .next_record()
            .map_err(scratch("read-archive-identity-set"))?;
        Ok(Self { reader, head })
    }

    /// Reports membership; queries must be in nondecreasing identity order.
    pub(super) fn contains(&mut self, id: ContentId) -> Result<bool, CampaignRepositoryError> {
        let key = ordered_id_record(id);
        while self.head.is_some_and(|head| head < key) {
            self.head = self
                .reader
                .next_record()
                .map_err(scratch("read-archive-identity-set"))?;
        }
        Ok(self.head == Some(key))
    }

    /// Returns the next identity in ascending order.
    pub(super) fn next(&mut self) -> Result<Option<ContentId>, CampaignRepositoryError> {
        let Some(head) = self.head else {
            return Ok(None);
        };
        self.head = self
            .reader
            .next_record()
            .map_err(scratch("read-archive-identity-set"))?;
        decode_ordered_id_record(&head)
            .map(Some)
            .map_err(scratch("decode-archive-identity-set"))
    }
}

/// Sorts and deduplicates identities, such as every selected object's children.
pub(super) struct IdSpill {
    sorter: ExternalSorter<ID_RECORD_BYTES>,
}

impl IdSpill {
    pub(super) fn new(storage: &SpillStorage, label: &'static str) -> Self {
        Self {
            sorter: ExternalSorter::new(storage, label, RUN_RECORDS),
        }
    }

    pub(super) fn push(&mut self, id: ContentId) -> Result<(), CampaignRepositoryError> {
        self.sorter
            .push(ordered_id_record(id))
            .map_err(scratch("spill-archive-identities"))
    }

    pub(super) fn finish(self) -> Result<SpillFile, CampaignRepositoryError> {
        self.sorter
            .finish()
            .map_err(scratch("sort-archive-identities"))
    }
}

/// Planning-time spool of canonical page envelopes in ordinal order.
pub(super) struct SpooledPages {
    frames: FrameReader,
}

impl SpooledPages {
    pub(super) fn open(file: &SpillFile) -> Result<Self, CampaignRepositoryError> {
        Ok(Self {
            frames: file.frames().map_err(scratch("open-archive-page-spool"))?,
        })
    }

    /// Returns the next spooled envelope after binding it to its manifest page ID.
    ///
    /// `expected` is the manifest's page at this ordinal, or `None` past the
    /// last page; the spool must end exactly there.
    pub(super) fn next_envelope(
        &mut self,
        expected: Option<CampaignArchiveInventoryPageId>,
    ) -> Result<Option<ObjectEnvelope>, CampaignRepositoryError> {
        let frame = self
            .frames
            .next_frame(MAX_ENVELOPE_BYTES as usize)
            .map_err(scratch("read-archive-page-spool"))?;
        let (Some(expected), Some(bytes)) = (expected, frame.as_ref()) else {
            return match (expected, frame) {
                (None, None) => Ok(None),
                _ => Err(integrity("campaign-archive-plan-page-spool-mismatch")),
            };
        };
        let envelope = ObjectEnvelope::from_canonical_bytes(bytes)?;
        if envelope.content_id() != expected.content_id()
            || envelope.record_kind() != CampaignRecordKind::ArchiveInventoryPage
        {
            return Err(integrity("campaign-archive-plan-page-spool-mismatch"));
        }
        Ok(Some(envelope))
    }
}

/// Where an [`InventoryCursor`] reads canonical page envelopes.
enum PageSource<'r> {
    /// Pages placed in a content store, authenticated by ID on every read.
    Store(&'r CampaignRepository),
    /// Pages spooled by planning and bound to the manifest's page IDs.
    Spool(SpooledPages),
}

/// Ordered replay of one disposition's entries, one canonical page at a time.
///
/// Every page is checked against its manifest ordinal and disposition, and
/// entries must ascend strictly across page boundaries, so a replay yields
/// exactly the inventory the manifest digests describe.
pub(super) struct InventoryCursor<'r, 'p> {
    source: PageSource<'r>,
    pages: &'p [CampaignArchiveInventoryPageId],
    disposition: ArchiveInventoryDisposition,
    next_ordinal: usize,
    entries: std::vec::IntoIter<ArchiveObjectEntry>,
    last: Option<ContentId>,
}

impl<'r, 'p> InventoryCursor<'r, 'p> {
    pub(super) fn store(
        repository: &'r CampaignRepository,
        pages: &'p [CampaignArchiveInventoryPageId],
        disposition: ArchiveInventoryDisposition,
    ) -> Self {
        Self::with_source(PageSource::Store(repository), pages, disposition)
    }

    pub(super) fn spool(
        file: &SpillFile,
        pages: &'p [CampaignArchiveInventoryPageId],
        disposition: ArchiveInventoryDisposition,
    ) -> Result<Self, CampaignRepositoryError> {
        Ok(Self::with_source(
            PageSource::Spool(SpooledPages::open(file)?),
            pages,
            disposition,
        ))
    }

    fn with_source(
        source: PageSource<'r>,
        pages: &'p [CampaignArchiveInventoryPageId],
        disposition: ArchiveInventoryDisposition,
    ) -> Self {
        Self {
            source,
            pages,
            disposition,
            next_ordinal: 0,
            entries: Vec::new().into_iter(),
            last: None,
        }
    }

    pub(super) fn next_entry(
        &mut self,
    ) -> Result<Option<ArchiveObjectEntry>, CampaignRepositoryError> {
        loop {
            if let Some(entry) = self.entries.next() {
                return Ok(Some(entry));
            }
            let Some(page) = self.next_page()? else {
                return Ok(None);
            };
            self.entries = page.into_entries().into_iter();
        }
    }

    fn next_page(
        &mut self,
    ) -> Result<Option<CampaignArchiveInventoryPage>, CampaignRepositoryError> {
        let expected = self.pages.get(self.next_ordinal).copied();
        let envelope = match &mut self.source {
            PageSource::Store(repository) => match expected {
                Some(id) => repository.require_record_kind(
                    id.content_id(),
                    CampaignRecordKind::ArchiveInventoryPage,
                )?,
                None => return Ok(None),
            },
            PageSource::Spool(spool) => match spool.next_envelope(expected)? {
                Some(envelope) => envelope,
                None => return Ok(None),
            },
        };
        let Some(id) = expected else {
            return Err(integrity("campaign-archive-plan-page-spool-mismatch"));
        };

        let page = CampaignArchiveInventoryPage::from_canonical_bytes(envelope.body())?;
        if page.id()? != id
            || page.disposition() != self.disposition
            || page.ordinal() as usize != self.next_ordinal
        {
            return Err(integrity("campaign-archive-inventory-page-mismatch"));
        }
        let first = page.entries().first().map(|entry| entry.id());
        if self
            .last
            .is_some_and(|last| first.is_none_or(|first| last >= first))
        {
            return Err(integrity("campaign-archive-inventory-order-mismatch"));
        }
        self.last = page.entries().last().map(|entry| entry.id());
        self.next_ordinal += 1;
        Ok(Some(page))
    }
}

/// Ascending union of a selected and an omitted cursor over one archive.
pub(super) struct MergedInventory<'r, 'p> {
    selected: InventoryCursor<'r, 'p>,
    omitted: InventoryCursor<'r, 'p>,
    next_selected: Option<ArchiveObjectEntry>,
    next_omitted: Option<ArchiveObjectEntry>,
}

impl<'r, 'p> MergedInventory<'r, 'p> {
    pub(super) fn new(
        mut selected: InventoryCursor<'r, 'p>,
        mut omitted: InventoryCursor<'r, 'p>,
    ) -> Result<Self, CampaignRepositoryError> {
        let next_selected = selected.next_entry()?;
        let next_omitted = omitted.next_entry()?;
        Ok(Self {
            selected,
            omitted,
            next_selected,
            next_omitted,
        })
    }

    /// Returns the next declared entry; an object in both inventories fails closed.
    pub(super) fn next(
        &mut self,
    ) -> Result<Option<(ArchiveInventoryDisposition, ArchiveObjectEntry)>, CampaignRepositoryError>
    {
        let take_selected = match (self.next_selected, self.next_omitted) {
            (None, None) => return Ok(None),
            (Some(selected), Some(omitted)) if selected.id() == omitted.id() => {
                return Err(integrity("campaign-archive-inventories-overlap"));
            }
            (Some(selected), Some(omitted)) => selected.id() < omitted.id(),
            (selected, _) => selected.is_some(),
        };
        if take_selected {
            let entry = mem::replace(&mut self.next_selected, self.selected.next_entry()?);
            Ok(entry.map(|entry| (ArchiveInventoryDisposition::Selected, entry)))
        } else {
            let entry = mem::replace(&mut self.next_omitted, self.omitted.next_entry()?);
            Ok(entry.map(|entry| (ArchiveInventoryDisposition::Omitted, entry)))
        }
    }
}

/// Builds one disposition's canonical pages and spools their envelopes.
pub(super) struct PageSpooler {
    disposition: ArchiveInventoryDisposition,
    writer: FrameWriter,
    pending: Vec<ArchiveObjectEntry>,
    pages: Vec<CampaignArchiveInventoryPageId>,
    length: InventoryLength,
}

/// One disposition's spooled pages and the measurements needed to digest them.
pub(super) struct SpooledInventory {
    disposition: ArchiveInventoryDisposition,
    pub(super) file: Arc<SpillFile>,
    pub(super) pages: Vec<CampaignArchiveInventoryPageId>,
    pub(super) length: InventoryLength,
}

impl PageSpooler {
    pub(super) fn new(
        storage: &SpillStorage,
        disposition: ArchiveInventoryDisposition,
    ) -> Result<Self, CampaignRepositoryError> {
        Ok(Self {
            disposition,
            writer: FrameWriter::create(storage, "archive-pages")
                .map_err(scratch("create-archive-page-spool"))?,
            pending: Vec::with_capacity(MAX_ARCHIVE_INVENTORY_PAGE_ENTRIES),
            pages: Vec::new(),
            length: InventoryLength::default(),
        })
    }

    /// Appends the next entry, which must follow every earlier entry in ID order.
    pub(super) fn push(
        &mut self,
        entry: ArchiveObjectEntry,
    ) -> Result<(), CampaignRepositoryError> {
        self.length.add(entry)?;
        self.pending.push(entry);
        if self.pending.len() == MAX_ARCHIVE_INVENTORY_PAGE_ENTRIES {
            self.flush()?;
        }
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<SpooledInventory, CampaignRepositoryError> {
        self.flush()?;
        let file = self
            .writer
            .finish()
            .map_err(scratch("finish-archive-page-spool"))?;
        Ok(SpooledInventory {
            disposition: self.disposition,
            file: Arc::new(file),
            pages: self.pages,
            length: self.length,
        })
    }

    fn flush(&mut self) -> Result<(), CampaignRepositoryError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let ordinal = u32::try_from(self.pages.len())
            .map_err(|_| integrity("campaign-archive-page-limit"))?;
        let entries = mem::replace(
            &mut self.pending,
            Vec::with_capacity(MAX_ARCHIVE_INVENTORY_PAGE_ENTRIES),
        );
        let page = CampaignArchiveInventoryPage::new(self.disposition, ordinal, entries)?;
        let envelope = ObjectEnvelope::for_archive_inventory_page(&page)?;
        self.pages
            .push(CampaignArchiveInventoryPageId::from_content_id(
                envelope.content_id(),
            )?);
        self.writer
            .push(&envelope.canonical_bytes())
            .map_err(scratch("spool-archive-page"))
    }
}

impl SpooledInventory {
    /// Digests the spooled inventory in a second pass over its pages.
    pub(super) fn summary(&self) -> Result<InventorySummary, CampaignRepositoryError> {
        let mut cursor = InventoryCursor::spool(&self.file, &self.pages, self.disposition)?;
        digest_inventory(&mut cursor, self.length)
    }
}

/// Digests one inventory replay whose shape a first pass measured.
pub(super) fn digest_inventory(
    cursor: &mut InventoryCursor<'_, '_>,
    length: InventoryLength,
) -> Result<InventorySummary, CampaignRepositoryError> {
    let mut digest = InventoryDigest::new(length)?;
    while let Some(entry) = cursor.next_entry()? {
        digest.add(entry);
    }
    Ok(InventorySummary {
        count: length.entries(),
        digest: digest.finish()?,
    })
}

#[cfg(test)]
mod tests;
