//! Authoritative packed-index root, its cached view, commits, and compaction.
//!
//! The logical index is an immutable sorted base plus an append-only journal
//! of later mutations. A sorted pack table records the live entry count and
//! exact length of every referenced pack. One small root record commits all
//! three by digest and length, and is replaced atomically for every mutation
//! by write, file fsync, rename, and directory fsync.
//!
//! ```text
//! .packed-admin/
//!   index-v2                      # PackIndexV2 root
//!   index-base-<digest>           # SortedFile of PackIndexBaseV2 records
//!   pack-table-<digest>           # SortedFile of PackTableV1 records
//!   index-journal-<base digest>   # PackIndexJournalV2
//! ```
//!
//! The root, base-record, and pack-table formats are defined in the
//! `index_records` module.
//!
//! Lookups consult the resident journal delta first and then binary-search
//! the base or pack table. The delta holds at most one entry and one pack per
//! journal record, and compaction folds it into a new base and pack table
//! once the journal reaches [`CompactionPolicy::threshold`] records, so
//! resident memory is bounded independently of the number of objects.

use std::collections::BTreeMap;
use std::collections::btree_map;
use std::fs;
use std::io::{self, Write};
use std::iter::Peekable;
use std::path::{Path, PathBuf};

use super::external_sort::ExternalSorter;
use super::index_records::{
    IndexRecord, IndexRoot, IndexTotals, PackRecord, PackState, root_digest,
};
use super::journal::{
    JOURNAL_RECORD_BYTES, JournalFile, JournalOperation, JournalRecord, encode_record,
    initial_chain, journal_header,
};
use super::sorted_file::{
    SortedFile, SortedFileIdentity, SortedFileIter, SortedFileWriter, SortedRecord,
};
use super::{
    ContentId, IndexEntry, MAX_PACK_ENTRIES, PackId, PackedRepackPlanId, StoreError,
    create_temporary, decode_hex, encode_hex, io_error, read_bounded_file, remove_temporary,
    sync_directory,
};

/// File name of the authoritative root record.
pub(super) const ROOT_FILE: &str = "index-v2";
const BASE_PREFIX: &str = "index-base-";
const PACK_TABLE_PREFIX: &str = "pack-table-";
const JOURNAL_PREFIX: &str = "index-journal-";
const ROOT_TEMPORARY_LABEL: &str = "index";
const OWNED_TEMPORARY_LABELS: [&str; 4] = ["index", "index-base", "pack-table", "index-journal"];

const MAX_ROOT_BYTES: u64 = 1_024;

/// Journal length bounds that trigger compaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CompactionPolicy {
    minimum_records: u64,
    maximum_records: u64,
}

impl CompactionPolicy {
    /// Production bounds: about 0.5 to 8 MiB of journal and resident delta.
    pub(super) const DEFAULT: Self = Self {
        minimum_records: 4_096,
        maximum_records: 65_536,
    };

    /// Builds a policy, clamping both bounds to at least one record.
    #[cfg(test)]
    pub(super) fn new(minimum_records: u64, maximum_records: u64) -> Self {
        let minimum_records = minimum_records.max(1);
        Self {
            minimum_records,
            maximum_records: maximum_records.max(minimum_records),
        }
    }

    /// Returns the journal length at which the next mutation compacts first.
    ///
    /// The threshold grows with the base so rewrite cost per mutation stays
    /// near one eighth of the base size, while the upper bound keeps resident
    /// journal state bounded for arbitrarily large stores.
    pub(super) fn threshold(self, base_records: u64) -> u64 {
        (base_records / 8).clamp(self.minimum_records, self.maximum_records)
    }
}

/// Immutable files named by one root.
struct IndexFiles {
    base: SortedFile<IndexRecord>,
    table: SortedFile<PackRecord>,
    journal: JournalFile,
}

/// Resident effect of the committed journal over the base and pack table.
#[derive(Default)]
struct JournalDelta {
    /// `None` marks a deletion relative to the base.
    entries: BTreeMap<ContentId, Option<IndexEntry>>,
    /// Absolute pack states; zero live entries marks an unreferenced pack.
    packs: BTreeMap<PackId, PackState>,
}

impl JournalDelta {
    fn get(&self, files: &IndexFiles, id: ContentId) -> Result<Option<IndexEntry>, StoreError> {
        match self.entries.get(&id) {
            Some(entry) => Ok(*entry),
            None => Ok(files.base.find(id)?.map(|record| record.entry)),
        }
    }

    fn pack(&self, files: &IndexFiles, pack: PackId) -> Result<Option<PackState>, StoreError> {
        let state = match self.packs.get(&pack) {
            Some(state) => Some(*state),
            None => files.table.find(pack)?.map(|record| record.state),
        };
        Ok(state.filter(|state| state.live_entries != 0))
    }

    /// Validates `record` against the current view and returns its pack's next state.
    fn effect(&self, files: &IndexFiles, record: &JournalRecord) -> Result<PackState, StoreError> {
        let current = self.get(files, record.id)?;
        let pack = self.pack(files, record.entry.pack)?;
        match record.operation {
            JournalOperation::Put => {
                if current.is_some() {
                    return Err(StoreError::Incompatible);
                }
                match pack {
                    None => Ok(PackState {
                        live_entries: 1,
                        physical_bytes: record.pack_physical_bytes,
                    }),
                    Some(state)
                        if state.physical_bytes == record.pack_physical_bytes
                            && state.live_entries < MAX_PACK_ENTRIES as u64 =>
                    {
                        Ok(PackState {
                            live_entries: state.live_entries + 1,
                            ..state
                        })
                    }
                    Some(_) => Err(StoreError::Incompatible),
                }
            }
            JournalOperation::Delete => match (current, pack) {
                (Some(entry), Some(state))
                    if entry == record.entry
                        && state.physical_bytes == record.pack_physical_bytes =>
                {
                    Ok(PackState {
                        live_entries: state.live_entries - 1,
                        ..state
                    })
                }
                _ => Err(StoreError::Incompatible),
            },
        }
    }

    fn install(&mut self, record: &JournalRecord, pack_state: PackState) {
        let entry = match record.operation {
            JournalOperation::Put => Some(record.entry),
            JournalOperation::Delete => None,
        };
        self.entries.insert(record.id, entry);
        self.packs.insert(record.entry.pack, pack_state);
    }
}

/// Authenticated view of one committed root.
pub(super) struct PackIndex {
    root: IndexRoot,
    root_bytes: Vec<u8>,
    files: IndexFiles,
    delta: JournalDelta,
}

impl PackIndex {
    /// Returns the committed root.
    pub(super) const fn root(&self) -> &IndexRoot {
        &self.root
    }

    /// Returns the digest that binds base, journal prefix, and pack table.
    pub(super) fn digest(&self) -> [u8; 32] {
        root_digest(&self.root_bytes)
    }

    /// Returns the current entry for `id`.
    pub(super) fn get(&self, id: ContentId) -> Result<Option<IndexEntry>, StoreError> {
        self.delta.get(&self.files, id)
    }

    /// Returns the state of `pack` when the index references it.
    pub(super) fn pack(&self, pack: PackId) -> Result<Option<PackState>, StoreError> {
        self.delta.pack(&self.files, pack)
    }

    /// Streams live entries in content-ID order.
    ///
    /// A complete iteration authenticates the whole base file.
    pub(super) fn entries(&self) -> Merged<'_, IndexRecord, Option<IndexEntry>> {
        Merged::new(
            self.files.base.iter(self.root.base_digest),
            &self.delta.entries,
            |id, entry| entry.map(|entry| IndexRecord { id, entry }),
        )
    }

    /// Streams referenced packs in pack-ID order.
    ///
    /// A complete iteration authenticates the whole pack table.
    pub(super) fn packs(&self) -> Merged<'_, PackRecord, PackState> {
        Merged::new(
            self.files.table.iter(self.root.pack_table_digest),
            &self.delta.packs,
            |pack, state| {
                (state.live_entries != 0).then_some(PackRecord {
                    pack,
                    state: *state,
                })
            },
        )
    }

    /// Discards any journal bytes beyond the committed length.
    pub(super) fn truncate_uncommitted_journal(&self) -> Result<bool, StoreError> {
        self.files
            .journal
            .truncate_uncommitted(self.root.journal_length)
    }

    fn file_names(&self) -> [String; 3] {
        root_file_names(&self.root)
    }
}

fn root_file_names(root: &IndexRoot) -> [String; 3] {
    [
        format!("{BASE_PREFIX}{}", encode_hex(root.base_digest)),
        format!("{PACK_TABLE_PREFIX}{}", encode_hex(root.pack_table_digest)),
        format!("{JOURNAL_PREFIX}{}", encode_hex(root.base_digest)),
    ]
}

/// Ordered merge of one sorted file with a resident override map.
pub(super) struct Merged<'a, R: SortedRecord, V> {
    base: SortedFileIter<'a, R>,
    head: Option<R>,
    base_done: bool,
    delta: Peekable<btree_map::Iter<'a, R::Key, V>>,
    materialize: fn(R::Key, &V) -> Option<R>,
    failed: bool,
}

impl<'a, R: SortedRecord, V> Merged<'a, R, V> {
    fn new(
        base: SortedFileIter<'a, R>,
        delta: &'a BTreeMap<R::Key, V>,
        materialize: fn(R::Key, &V) -> Option<R>,
    ) -> Self {
        Self {
            base,
            head: None,
            base_done: false,
            delta: delta.iter().peekable(),
            materialize,
            failed: false,
        }
    }

    fn next_record(&mut self) -> Result<Option<R>, StoreError> {
        loop {
            if self.head.is_none() && !self.base_done {
                match self.base.next() {
                    Some(record) => self.head = Some(record?),
                    None => self.base_done = true,
                }
            }

            let delta_key = self.delta.peek().map(|(key, _value)| **key);
            let take_delta = match (self.head, delta_key) {
                (None, None) => return Ok(None),
                (Some(_), None) => false,
                (None, Some(_)) => true,
                (Some(head), Some(key)) => key <= head.key(),
            };
            if !take_delta {
                return Ok(self.head.take());
            }

            let Some((key, value)) = self.delta.next() else {
                return Err(StoreError::Incompatible);
            };
            if self.head.is_some_and(|head| head.key() == *key) {
                self.head = None;
            }
            if let Some(record) = (self.materialize)(*key, value) {
                return Ok(Some(record));
            }
        }
    }
}

impl<R: SortedRecord, V> Iterator for Merged<'_, R, V> {
    type Item = Result<R, StoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let result = self.next_record().transpose();
        if matches!(result, Some(Err(_))) {
            self.failed = true;
        }
        result
    }
}

/// Order in which a build receives pack records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PackOrder {
    /// Records arrive strictly increasing by pack ID.
    Sorted,
    /// Records arrive in any order and are externally sorted.
    Unsorted,
}

enum PackSink {
    // Boxed because the writer's running digest dwarfs the sorter handle.
    Sorted(Box<SortedFileWriter<PackRecord>>),
    Unsorted(ExternalSorter<PackRecord>),
}

/// Staged base, pack table, and empty journal for one new root.
pub(super) struct IndexBuild {
    admin: PathBuf,
    identity: SortedFileIdentity,
    base: SortedFileWriter<IndexRecord>,
    packs: PackSink,
    totals: IndexTotals,
}

impl IndexBuild {
    /// Appends the next entry in strictly increasing content-ID order.
    pub(super) fn push_entry(
        &mut self,
        id: ContentId,
        entry: IndexEntry,
    ) -> Result<(), StoreError> {
        self.base.push(IndexRecord { id, entry })?;
        self.totals.logical_objects = self
            .totals
            .logical_objects
            .checked_add(1)
            .ok_or(StoreError::Quota)?;
        self.totals.logical_bytes = self
            .totals
            .logical_bytes
            .checked_add(entry.length)
            .ok_or(StoreError::Quota)?;
        Ok(())
    }

    /// Records one referenced pack.
    pub(super) fn push_pack(&mut self, pack: PackId, state: PackState) -> Result<(), StoreError> {
        let record = PackRecord { pack, state };
        match &mut self.packs {
            PackSink::Sorted(writer) => writer.push(record)?,
            PackSink::Unsorted(sorter) => sorter.push(record)?,
        }
        self.totals.packs = self.totals.packs.checked_add(1).ok_or(StoreError::Quota)?;
        self.totals.physical_bytes = self
            .totals
            .physical_bytes
            .checked_add(state.physical_bytes)
            .ok_or(StoreError::Quota)?;
        Ok(())
    }

    /// Makes every staged file durable and returns the uncommitted root fields.
    pub(super) fn finish(self) -> Result<StagedIndex, StoreError> {
        let Self {
            admin,
            identity,
            base,
            packs,
            totals,
        } = self;
        let base_digest = base.finish(BASE_PREFIX)?;
        let pack_table_digest = match packs {
            PackSink::Sorted(writer) => writer.finish(PACK_TABLE_PREFIX)?,
            PackSink::Unsorted(sorter) => {
                let mut writer =
                    SortedFileWriter::<PackRecord>::create(&admin, "pack-table", identity)?;
                for record in sorter.finish()? {
                    writer.push(record?)?;
                }
                writer.finish(PACK_TABLE_PREFIX)?
            }
        };

        let header = journal_header(identity.configuration, identity.instance, base_digest);
        let journal_path = admin.join(format!("{JOURNAL_PREFIX}{}", encode_hex(base_digest)));
        JournalFile::create(&admin, &journal_path, &header)?;
        sync_directory(&admin)?;

        Ok(StagedIndex {
            instance: identity.instance,
            base_digest,
            pack_table_digest,
            journal_length: header.len() as u64,
            journal_chain: initial_chain(&header),
            totals,
        })
    }
}

/// Durable files of a new index that no root names yet.
pub(super) struct StagedIndex {
    instance: [u8; 32],
    base_digest: [u8; 32],
    pack_table_digest: [u8; 32],
    journal_length: u64,
    journal_chain: [u8; 32],
    totals: IndexTotals,
}

impl StagedIndex {
    /// Returns the root that would commit these files.
    pub(super) const fn root(
        &self,
        generation: u64,
        last_repack_plan: Option<PackedRepackPlanId>,
    ) -> IndexRoot {
        IndexRoot {
            instance: self.instance,
            generation,
            last_repack_plan,
            base_digest: self.base_digest,
            base_records: self.totals.logical_objects,
            pack_table_digest: self.pack_table_digest,
            pack_table_records: self.totals.packs,
            journal_length: self.journal_length,
            journal_records: 0,
            journal_chain: self.journal_chain,
            totals: self.totals,
        }
    }
}

/// Index file operations rooted at one administrative directory.
pub(super) struct IndexDirectory<'a> {
    pub(super) admin: &'a Path,
    pub(super) configuration: [u8; 32],
    pub(super) policy: CompactionPolicy,
}

impl IndexDirectory<'_> {
    /// Returns the root record path.
    pub(super) fn root_path(&self) -> PathBuf {
        self.admin.join(ROOT_FILE)
    }

    /// Loads the committed root, reusing `cached` when it is still current.
    ///
    /// An unchanged root reuses the cached view without I/O beyond reading
    /// the root. A longer journal over the same base replays only the new
    /// committed records. The directory is synced the first time a root is
    /// observed, so a view never acts on a root that could still roll back.
    pub(super) fn load(&self, cached: Option<PackIndex>) -> Result<PackIndex, StoreError> {
        let bytes = read_bounded_file(&self.root_path(), MAX_ROOT_BYTES, "read packed index root")?;
        match cached {
            Some(cached) if cached.root_bytes == bytes => Ok(cached),
            cached => {
                let root = IndexRoot::decode(&bytes, self.configuration)?;
                sync_directory(self.admin)?;
                match cached {
                    Some(cached) if extends(&cached.root, &root) => {
                        self.extend_view(cached, root, bytes)
                    }
                    _ => self.open_view(root),
                }
            }
        }
    }

    /// Opens the files `root` names and replays its committed journal.
    pub(super) fn open_view(&self, root: IndexRoot) -> Result<PackIndex, StoreError> {
        let [base_name, table_name, journal_name] = root_file_names(&root);
        let base = SortedFile::<IndexRecord>::open(
            &self.admin.join(base_name),
            self.configuration,
            root.instance,
        )?;
        let table = SortedFile::<PackRecord>::open(
            &self.admin.join(table_name),
            self.configuration,
            root.instance,
        )?;
        if base.record_count() != root.base_records
            || table.record_count() != root.pack_table_records
            || base.generation() > root.generation
            || table.generation() != base.generation()
        {
            return Err(StoreError::Incompatible);
        }
        let header = journal_header(self.configuration, root.instance, root.base_digest);
        let journal = JournalFile::open(&self.admin.join(journal_name), &header)?;

        let root_bytes = root.encode(self.configuration);
        let mut view = PackIndex {
            root,
            root_bytes,
            files: IndexFiles {
                base,
                table,
                journal,
            },
            delta: JournalDelta::default(),
        };
        let header_length = header.len() as u64;
        replay_into(&mut view, header_length, initial_chain(&header), 0)?;
        Ok(view)
    }

    fn extend_view(
        &self,
        mut cached: PackIndex,
        root: IndexRoot,
        root_bytes: Vec<u8>,
    ) -> Result<PackIndex, StoreError> {
        let from = cached.root.journal_length;
        let chain = cached.root.journal_chain;
        let replayed = cached.root.journal_records;
        cached.root = root;
        cached.root_bytes = root_bytes;
        replay_into(&mut cached, from, chain, replayed)?;
        Ok(cached)
    }

    /// Starts a new base and pack table at `generation`.
    pub(super) fn build(
        &self,
        instance: [u8; 32],
        generation: u64,
        pack_order: PackOrder,
    ) -> Result<IndexBuild, StoreError> {
        let identity = SortedFileIdentity {
            configuration: self.configuration,
            instance,
            generation,
        };
        let base = SortedFileWriter::create(self.admin, "index-base", identity)?;
        let packs = match pack_order {
            PackOrder::Sorted => PackSink::Sorted(Box::new(SortedFileWriter::create(
                self.admin,
                "pack-table",
                identity,
            )?)),
            PackOrder::Unsorted => PackSink::Unsorted(ExternalSorter::new(self.admin)),
        };
        Ok(IndexBuild {
            admin: self.admin.to_path_buf(),
            identity,
            base,
            packs,
            totals: IndexTotals::default(),
        })
    }

    /// Atomically makes `view`'s root authoritative.
    ///
    /// A publication error is reconciled by rereading the visible root, so
    /// a rename that completed before a later sync failure is not reported
    /// as a failed switch.
    pub(super) fn publish(&self, view: &PackIndex) -> Result<(), StoreError> {
        self.publish_root_reconciled(&view.root_bytes)
    }

    fn publish_root_reconciled(&self, bytes: &[u8]) -> Result<(), StoreError> {
        match self.publish_root(bytes) {
            Ok(()) => Ok(()),
            Err(error) => {
                match read_bounded_file(&self.root_path(), MAX_ROOT_BYTES, "read packed index root")
                {
                    Ok(visible) if visible == bytes => sync_directory(self.admin),
                    Ok(_) | Err(_) => Err(error),
                }
            }
        }
    }

    fn publish_root(&self, bytes: &[u8]) -> Result<(), StoreError> {
        let (temporary, mut output) = create_temporary(self.admin, ROOT_TEMPORARY_LABEL)?;
        let result = (|| {
            output
                .write_all(bytes)
                .and_then(|()| output.sync_all())
                .map_err(|source| io_error("write packed index root", &temporary, source))?;
            let path = self.root_path();
            fs::rename(&temporary, &path)
                .map_err(|source| io_error("publish packed index root", &path, source))?;
            sync_directory(self.admin)
        })();
        remove_temporary(&temporary, result.is_ok())?;
        result
    }

    /// Durably commits one mutation, compacting first when the journal is full.
    ///
    /// The record is appended and synced before the root that names it is
    /// published. An interruption between the two leaves an uncommitted
    /// journal tail that the next append or initialization discards.
    pub(super) fn commit(
        &self,
        index: &mut PackIndex,
        record: JournalRecord,
    ) -> Result<(), StoreError> {
        if index.root.journal_records >= self.policy.threshold(index.root.base_records) {
            *index = self.compact(index)?;
        }

        let pack_state = index.delta.effect(&index.files, &record)?;
        let totals = index.root.totals.after(&record, pack_state)?;
        let (bytes, chain) = encode_record(&record, index.root.journal_chain);
        index
            .files
            .journal
            .append(index.root.journal_length, &bytes)?;

        #[cfg(feature = "destructive-recovery-faults")]
        super::inject_fault(super::JOURNAL_TAIL_INTERRUPTION_TRIGGER);

        let mut next = index.root.clone();
        next.generation = next.generation.checked_add(1).ok_or(StoreError::Quota)?;
        next.last_repack_plan = None;
        next.journal_length = next
            .journal_length
            .checked_add(JOURNAL_RECORD_BYTES as u64)
            .ok_or(StoreError::Quota)?;
        next.journal_records = next
            .journal_records
            .checked_add(1)
            .ok_or(StoreError::Quota)?;
        next.journal_chain = chain;
        next.totals = totals;
        let next_bytes = next.encode(self.configuration);
        self.publish_root_reconciled(&next_bytes)?;

        index.root = next;
        index.root_bytes = next_bytes;
        index.delta.install(&record, pack_state);
        Ok(())
    }

    /// Folds the journal into a new base and pack table at the same generation.
    ///
    /// The logical content is unchanged, so the generation stays the same;
    /// the merge recomputes every total and must match the committed root.
    fn compact(&self, index: &PackIndex) -> Result<PackIndex, StoreError> {
        let root = index.root();
        let mut build = self.build(root.instance, root.generation, PackOrder::Sorted)?;
        for record in index.entries() {
            let record = record?;
            build.push_entry(record.id, record.entry)?;
        }
        for record in index.packs() {
            let record = record?;
            build.push_pack(record.pack, record.state)?;
        }
        let staged = build.finish()?;
        let view = self.open_view(staged.root(root.generation, root.last_repack_plan))?;
        if view.root.totals != root.totals {
            return Err(StoreError::Incompatible);
        }

        #[cfg(feature = "destructive-recovery-faults")]
        super::inject_fault(super::COMPACTION_INTERRUPTION_TRIGGER);

        self.publish(&view)?;
        // The switch is committed. A superseded name that cannot be removed
        // is unreferenced and the next exclusive sweep reclaims it, so a
        // removal failure must not fail the mutation that triggered compaction.
        let _ignored = self.remove_superseded(root, view.root());
        Ok(view)
    }

    /// Removes the files of `previous` that `current` no longer names.
    pub(super) fn remove_superseded(
        &self,
        previous: &IndexRoot,
        current: &IndexRoot,
    ) -> Result<(), StoreError> {
        let retained = root_file_names(current);
        let mut removed = false;
        for name in root_file_names(previous) {
            if retained.contains(&name) {
                continue;
            }
            let path = self.admin.join(&name);
            match fs::remove_file(&path) {
                Ok(()) => removed = true,
                Err(source) if source.kind() == io::ErrorKind::NotFound => {}
                Err(source) => return Err(io_error("remove superseded index file", &path, source)),
            }
        }
        if removed {
            sync_directory(self.admin)?;
        }
        Ok(())
    }

    /// Removes owned index files and staging names that `index` does not name.
    ///
    /// The caller holds the lifecycle lock exclusively, so no compaction or
    /// publication can own a staging name concurrently. Unknown names are
    /// left untouched.
    pub(super) fn sweep_orphans(&self, index: &PackIndex) -> Result<u64, StoreError> {
        let retained = index.file_names();
        let mut removed = 0_u64;
        for entry in fs::read_dir(self.admin)
            .map_err(|source| io_error("list packed index files", self.admin, source))?
        {
            let entry =
                entry.map_err(|source| io_error("read packed index entry", self.admin, source))?;
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if !is_owned_index_name(&name) || retained.contains(&name) {
                continue;
            }
            let file_type = entry
                .file_type()
                .map_err(|source| io_error("inspect packed index entry", &entry.path(), source))?;
            if !file_type.is_file() {
                return Err(StoreError::InvalidComposition {
                    reason: "packed index path is not a regular file",
                });
            }
            fs::remove_file(entry.path())
                .map_err(|source| io_error("remove orphan index file", &entry.path(), source))?;
            removed = removed.checked_add(1).ok_or(StoreError::Quota)?;
        }
        if removed != 0 {
            sync_directory(self.admin)?;
        }
        Ok(removed)
    }
}

/// Returns whether `next` only appends journal records to `previous`.
fn extends(previous: &IndexRoot, next: &IndexRoot) -> bool {
    previous.instance == next.instance
        && previous.base_digest == next.base_digest
        && previous.pack_table_digest == next.pack_table_digest
        && previous.journal_length <= next.journal_length
        && previous.journal_records <= next.journal_records
}

/// Replays committed records from `from` and checks the root's chain and count.
fn replay_into(
    view: &mut PackIndex,
    from: u64,
    chain: [u8; 32],
    replayed: u64,
) -> Result<(), StoreError> {
    let files = &view.files;
    let delta = &mut view.delta;
    let (chain, records) =
        files
            .journal
            .replay(from, view.root.journal_length, chain, |record| {
                let pack_state = delta.effect(files, &record)?;
                delta.install(&record, pack_state);
                Ok(())
            })?;
    if chain != view.root.journal_chain
        || replayed.checked_add(records) != Some(view.root.journal_records)
    {
        return Err(StoreError::Incompatible);
    }
    Ok(())
}

fn is_owned_index_name(name: &str) -> bool {
    let digest_named = [BASE_PREFIX, PACK_TABLE_PREFIX, JOURNAL_PREFIX]
        .iter()
        .any(|prefix| name.strip_prefix(prefix).and_then(decode_hex).is_some());
    digest_named
        || OWNED_TEMPORARY_LABELS
            .iter()
            .any(|label| super::is_temporary_name(name, label))
}
