//! Disk-backed membership for authenticated GC marking.
//!
//! The caller's quota-bound scratch CAS owns the RAM graph's mark tree.
//! A retained Merkle root authenticates every membership lookup. Planning and
//! apply use the same authenticated traversal under their ref inventory fence;
//! storage failure aborts the operation before any deletion is admitted.

use std::io;
use std::sync::Arc;

use crucible_campaign::{
    CampaignHash, CampaignRepository, MAX_CAMPAIGN_CLOSURE_OBJECTS, MerkleMap, MerkleMapRoot,
};
use crucible_cas::content_store::{
    ContentId, DurabilityRequirement, ImmutableBlobBackend, RefInventoryFence, StoreError,
};
use crucible_cas::owned_decode::DecodeBudget;
use crucible_cas::ram::{RamStore, RamStoreError, RamStoreLimits};

use super::CampaignGcOperationContext;

#[cfg(test)]
mod metadata_lifecycle;

#[cfg(test)]
mod batched_tests;

#[cfg(test)]
mod membership_tests;

pub(super) struct Reachability {
    map: MerkleMap,
    root: MerkleMapRoot,
    #[cfg(test)]
    directory: Option<tempfile::TempDir>,
    original: DecodeBudget,
}

impl Reachability {
    pub(super) fn authenticate(
        repository: &CampaignRepository,
        roots: impl IntoIterator<Item = ContentId>,
        direct: impl IntoIterator<Item = ContentId>,
        inventory: &dyn RefInventoryFence,
        operation: &CampaignGcOperationContext<'_>,
    ) -> Result<Self, StoreError> {
        operation.check()?;
        let mut marks = Self::with_backend(operation.marks(), operation.original())?;
        let mut pending = PendingMarks::new(operation)?;
        let closure = repository
            .authenticated_storage_closure_with_boundary(roots, inventory, &mut || {
                operation.check().map_err(Into::into)
            })
            .map_err(|error| match error {
                crucible_campaign::CampaignRepositoryError::Store(source)
                | crucible_campaign::CampaignRepositoryError::Ram(RamStoreError::Store(source)) => {
                    source
                }
                other => marks.failure("authenticate GC closure", other),
            })?;
        for id in closure.objects().iter().copied().chain(direct) {
            operation.check()?;
            pending.insert(&mut marks, id, operation)?;
        }

        if closure.ram_roots().is_empty() {
            pending.flush(&mut marks, operation)?;
            return Ok(marks);
        }

        let ram = RamStore::new(
            repository.blob_backend(),
            DurabilityRequirement::new(1, false)?,
            RamStoreLimits {
                maximum_logical_bytes: u64::MAX,
                maximum_object_visits: MAX_CAMPAIGN_CLOSURE_OBJECTS as u64,
                ..RamStoreLimits::default()
            },
        )
        .map_err(|error| marks.failure("open GC RAM inventory", error))?;
        for root in closure.ram_roots() {
            ram.visit_inventory_graph(
                *root,
                inventory,
                operation.original(),
                &mut || operation.check().map_err(Into::into),
                &mut |id| {
                    operation.check()?;
                    pending
                        .insert(&mut marks, id, operation)
                        .map_err(Into::into)
                },
            )
            .map_err(|error| match error {
                RamStoreError::Store(source) => source,
                other => marks.failure("authenticate GC RAM graph", other),
            })?;
        }
        pending.flush(&mut marks, operation)?;
        Ok(marks)
    }

    fn with_backend(
        backend: Arc<dyn ImmutableBlobBackend>,
        original: &DecodeBudget,
    ) -> Result<Self, StoreError> {
        original
            .verify_live()
            .map_err(|error| mark_admission(original, error))?;
        backend.metadata_resources()?;
        let account = original
            .child()
            .map_err(|error| mark_admission(original, error))?;
        let _scope = account.enter();
        let map = MerkleMap::new(backend);
        let root = map.empty().map_err(|source| StoreError::StreamIo {
            operation: "initialize GC mark tree",
            source: io::Error::other(source),
        })?;
        account
            .check()
            .map_err(|error| mark_admission(&account, error))?;
        Ok(Self {
            map,
            root,
            #[cfg(test)]
            directory: None,
            original: original.clone(),
        })
    }

    #[cfg(test)]
    fn new() -> Result<Self, StoreError> {
        use crate::exact_checkpoint_store::test_support::{
            fixture_metadata_backend, fixture_ram_root_resources,
        };

        let resources = fixture_ram_root_resources().map_err(|source| StoreError::Supervision {
            source: Box::new(source),
        })?;
        let original = DecodeBudget::for_store(resources.clone()).map_err(|source| {
            StoreError::DecodeAdmission {
                source,
                custody: None,
            }
        })?;
        let directory = tempfile::tempdir().map_err(|source| StoreError::Io {
            operation: "create component GC mark directory",
            path: std::env::temp_dir(),
            source,
        })?;
        let backend = fixture_metadata_backend(
            Arc::new(crucible_cas::content_store::SqliteBlobBackend::open(
                "component-gc-marks",
                directory.path(),
                &crucible_cas::content_store::fixture_sqlite_heap()
                    .expect("authored SQLite fixture process"),
            )?),
            resources,
        );
        let mut marks = Self::with_backend(backend, &original)?;
        marks.directory = Some(directory);
        Ok(marks)
    }

    #[cfg(test)]
    fn insert(&mut self, id: ContentId) -> Result<(), StoreError> {
        let account = mark_account(&self.original)?;
        let _scope = account.enter();
        // Keeping the immutable root in memory authenticates both presence and
        // absence. A damaged SQLite row must never turn a reachable object into
        // an apparently absent mark that could authorize deletion.
        let root = self
            .map
            .insert(self.root.content_id(), mark_key(id), id)
            .map_err(|source| self.failure("insert GC mark", source))?;
        account
            .check()
            .map_err(|error| mark_admission(&account, error))?;
        if root.entry_count() > MAX_CAMPAIGN_CLOSURE_OBJECTS as u64 {
            return Err(StoreError::Quota);
        }
        self.root = root;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn contains(&self, id: &ContentId) -> Result<bool, StoreError> {
        let account = mark_account(&self.original)?;
        let _scope = account.enter();
        let value = self
            .map
            .get(self.root.content_id(), mark_key(*id))
            .map_err(|source| self.failure("authenticate GC mark", source))?;
        account
            .check()
            .map_err(|error| mark_admission(&account, error))?;
        match value {
            None => Ok(false),
            Some(found) if found == *id => Ok(true),
            Some(_) => Err(StoreError::Corrupt {
                id: self.root.content_id(),
            }),
        }
    }

    pub(super) fn contains_with_boundary(
        &self,
        id: &ContentId,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<bool, StoreError> {
        let account = mark_account(&self.original)?;
        let _scope = account.enter();
        let value = self
            .map
            .get_with_boundary(self.root.content_id(), mark_key(*id), &account, boundary)
            .map_err(|source| self.failure("authenticate GC mark", source))?;
        account
            .check()
            .map_err(|error| mark_admission(&account, error))?;
        match value {
            None => Ok(false),
            Some(found) if found == *id => Ok(true),
            Some(_) => Err(StoreError::Corrupt {
                id: self.root.content_id(),
            }),
        }
    }

    pub(super) fn len(&self) -> u64 {
        self.root.entry_count()
    }

    fn failure(
        &self,
        operation: &'static str,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> StoreError {
        StoreError::StreamIo {
            operation,
            source: io::Error::other(source),
        }
    }
}

// A fixed first-byte table coalesces sixteen neighboring mature pages under
// one canonical first-nibble branch. Small passes retain the original 64-entry
// page; promotion begins after one page per first-level trie branch. Capacity
// never follows RAM size. Both vectors close before their original credits, and a failed
// publication leaves every unaccepted entry intact.
type MarkEntry = (CampaignHash, ContentId);

const MARK_PREFIXES: usize = 1 << u8::BITS;
const MARK_PAGE: usize = MerkleMap::MAX_CHECKED_BATCH_UPSERTS;
const MARK_SLOTS: usize = MARK_PREFIXES * MARK_PAGE;
const MARK_GROUP_PREFIXES: usize = 16;
const MARK_GROUP_PAGE: usize = MerkleMap::MAX_CHECKED_PREFIX_UPSERTS;
const MARK_PROMOTION: usize = (1 << 4) * MARK_PAGE;

struct PendingMarks {
    slots: Vec<Option<MarkEntry>>,
    page: Vec<MarkEntry>,
    counts: [u8; MARK_PREFIXES],
    observed: usize,
    staged: usize,
    _prefix_credit: Option<crucible_cas::owned_decode::ResourceLoan>,
    _credit: crucible_cas::owned_decode::ResourceLoan,
}

impl PendingMarks {
    fn initial_bytes() -> Result<u64, StoreError> {
        MARK_PAGE
            .checked_mul(std::mem::size_of::<MarkEntry>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(StoreError::Quota)
    }

    fn prefix_bytes() -> Result<u64, StoreError> {
        MARK_SLOTS
            .checked_mul(std::mem::size_of::<Option<MarkEntry>>())
            .and_then(|bytes| {
                bytes.checked_add(MARK_GROUP_PAGE.checked_mul(std::mem::size_of::<MarkEntry>())?)
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(StoreError::Quota)
    }

    fn new(operation: &CampaignGcOperationContext<'_>) -> Result<Self, StoreError> {
        let credit = operation.reserve_bytes(Self::initial_bytes()?)?;
        let mut page = Vec::new();
        page.try_reserve_exact(MARK_PAGE)
            .map_err(allocation_error)?;
        operation.check()?;
        Ok(Self {
            slots: Vec::new(),
            page,
            counts: [0; MARK_PREFIXES],
            observed: 0,
            staged: 0,
            _prefix_credit: None,
            _credit: credit,
        })
    }

    fn promote(&mut self, operation: &CampaignGcOperationContext<'_>) -> Result<(), StoreError> {
        let credit = operation.reserve_bytes(Self::prefix_bytes()?)?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(MARK_SLOTS)
            .map_err(allocation_error)?;
        slots.resize(MARK_SLOTS, None);
        // The old 64-entry allocation remains paid while its replacement is
        // prepared. Both local allocations close before this new credit on error.
        let mut page = Vec::new();
        page.try_reserve_exact(MARK_GROUP_PAGE)
            .map_err(allocation_error)?;
        operation.check()?;
        self.page = page;
        self.slots = slots;
        self._prefix_credit = Some(credit);
        Ok(())
    }

    fn insert(
        &mut self,
        marks: &mut Reachability,
        id: ContentId,
        operation: &CampaignGcOperationContext<'_>,
    ) -> Result<(), StoreError> {
        operation.check()?;
        if self.slots.is_empty() && self.observed >= MARK_PROMOTION {
            // Promotion is allowed only after the initial page has committed.
            // A retained failed page must complete before admitting another ID.
            if !self.page.is_empty() {
                self.publish_page(marks, operation)?;
            }
            self.promote(operation)?;
        }
        self.observed = self.observed.checked_add(1).ok_or(StoreError::Quota)?;
        let key = mark_key(id);
        if self.slots.is_empty() {
            if self.page.len() == MARK_PAGE {
                self.publish_page(marks, operation)?;
            }
            self.page.push((key, id));
            self.staged += 1;
            if self.page.len() == MARK_PAGE {
                self.publish_page(marks, operation)?;
            }
            return Ok(());
        }

        let prefix = usize::from(key.as_bytes()[0]);
        let start = prefix * MARK_PAGE;
        let position = (start..start + MARK_PAGE)
            .find(|position| self.slots[*position].is_none())
            .ok_or(StoreError::Quota)?;
        self.slots[position] = Some((key, id));
        self.counts[prefix] += 1;
        self.staged += 1;
        if usize::from(self.counts[prefix]) == MARK_PAGE {
            self.publish_group(marks, prefix / MARK_GROUP_PREFIXES, operation)?;
        }
        Ok(())
    }

    fn flush(
        &mut self,
        marks: &mut Reachability,
        operation: &CampaignGcOperationContext<'_>,
    ) -> Result<(), StoreError> {
        if self.staged == 0 {
            return Ok(());
        }
        if self.slots.is_empty() {
            return self.publish_page(marks, operation);
        }
        for group in 0..MARK_PREFIXES / MARK_GROUP_PREFIXES {
            let start = group * MARK_GROUP_PREFIXES;
            if self.counts[start..start + MARK_GROUP_PREFIXES]
                .iter()
                .any(|count| *count != 0)
            {
                self.publish_group(marks, group, operation)?;
            }
        }
        Ok(())
    }

    fn publish_group(
        &mut self,
        marks: &mut Reachability,
        group: usize,
        operation: &CampaignGcOperationContext<'_>,
    ) -> Result<(), StoreError> {
        operation.check()?;
        let first = group * MARK_GROUP_PREFIXES;
        let end = first + MARK_GROUP_PREFIXES;
        self.page.clear();
        for prefix in first..end {
            operation.check()?;
            let start = prefix * MARK_PAGE;
            self.page.extend(
                self.slots[start..start + MARK_PAGE]
                    .iter()
                    .flatten()
                    .copied(),
            );
        }
        let positions = self.page.len();
        self.page.sort_unstable_by_key(|entry| entry.0);
        if self
            .page
            .windows(2)
            .any(|pair| pair[0].0 == pair[1].0 && pair[0].1 != pair[1].1)
        {
            return Err(StoreError::Corrupt {
                id: marks.root.content_id(),
            });
        }
        self.page.dedup_by_key(|entry| entry.0);
        let account = mark_account(&marks.original)?;
        let root = marks
            .map
            .insert_prefix_batch_with_boundary(
                marks.root.content_id(),
                &self.page,
                &account,
                &mut || operation.check(),
            )
            .map_err(|source| marks.failure("insert GC mark batch", source))?;
        account
            .check()
            .map_err(|error| mark_admission(&account, error))?;
        operation.check()?;
        if root.entry_count() > MAX_CAMPAIGN_CLOSURE_OBJECTS as u64 {
            return Err(StoreError::Quota);
        }

        marks.root = root;
        for prefix in first..end {
            let start = prefix * MARK_PAGE;
            self.slots[start..start + MARK_PAGE].fill(None);
            self.counts[prefix] = 0;
        }
        self.staged -= positions;
        self.page.clear();
        Ok(())
    }

    fn publish_page(
        &mut self,
        marks: &mut Reachability,
        operation: &CampaignGcOperationContext<'_>,
    ) -> Result<(), StoreError> {
        operation.check()?;
        self.page.sort_unstable_by_key(|entry| entry.0);
        if self
            .page
            .windows(2)
            .any(|pair| pair[0].0 == pair[1].0 && pair[0].1 != pair[1].1)
        {
            return Err(StoreError::Corrupt {
                id: marks.root.content_id(),
            });
        }
        self.page.dedup_by_key(|entry| entry.0);
        let account = mark_account(&marks.original)?;
        let root = marks
            .map
            .insert_batch_with_boundary(marks.root.content_id(), &self.page, &account, &mut || {
                operation.check()
            })
            .map_err(|source| marks.failure("insert GC mark batch", source))?;
        account
            .check()
            .map_err(|error| mark_admission(&account, error))?;
        operation.check()?;
        if root.entry_count() > MAX_CAMPAIGN_CLOSURE_OBJECTS as u64 {
            return Err(StoreError::Quota);
        }
        marks.root = root;
        self.staged = 0;
        self.page.clear();
        Ok(())
    }
}

fn allocation_error(source: std::collections::TryReserveError) -> StoreError {
    StoreError::StreamIo {
        operation: "allocate bounded GC mark prefixes",
        source: io::Error::other(source),
    }
}

// Mark operations return only scalar identities. Their decoded nodes, source
// handles and publication buffers close before this child account; immutable
// backend copies retain their own original-account custody independently.
fn mark_account(original: &DecodeBudget) -> Result<DecodeBudget, StoreError> {
    original
        .verify_live()
        .map_err(|error| mark_admission(original, error))?;
    original
        .child()
        .map_err(|error| mark_admission(original, error))
}

fn mark_admission(
    original: &DecodeBudget,
    source: crucible_cas::owned_decode::DecodeAdmissionError,
) -> StoreError {
    StoreError::DecodeAdmission {
        source,
        custody: Some(original.custody()),
    }
}

fn mark_key(id: ContentId) -> CampaignHash {
    // Marks are private to one pass. A fixed stack representation avoids an
    // owning display-string allocation for every physical page in the graph.
    let kind = id.kind().as_str().as_bytes();
    let mut fields = [0_u8; 1 + 17 + 4 + 32];
    fields[0] = kind.len() as u8;
    fields[1..1 + kind.len()].copy_from_slice(kind);
    fields[18..22].copy_from_slice(&id.schema_version().to_be_bytes());
    fields[22..].copy_from_slice(&id.digest());
    CampaignHash::derive("crucible.gc.typed-mark.v2", &fields)
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- reachability regression fixtures panic only when required mark-database setup or authenticated inventory assertions fail.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crucible_cas::content_store::ObjectKind;

    #[test]
    fn disk_marks_preserve_typed_identity_and_count_shared_content_once() {
        let mut marks = Reachability::new().expect("mark database");
        let page = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"same bytes");
        let tree = ContentId::for_bytes(ObjectKind::RamTree, 1, b"same bytes");
        let other = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"other bytes");

        marks.insert(page).expect("first page");
        marks.insert(page).expect("shared page");
        marks.insert(tree).expect("distinct kind");

        assert_eq!(marks.len(), 2);
        assert!(marks.contains(&page).expect("page membership"));
        assert!(marks.contains(&tree).expect("tree membership"));
        assert!(!marks.contains(&other).expect("missing membership"));
    }

    #[test]
    fn missing_mark_tree_never_means_an_unreachable_object() {
        let mut marks = Reachability::new().expect("mark database");
        let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"page");
        marks.insert(id).expect("reachable page");
        // Remove the actual database contents independently of the retained
        // root. A missing authenticated path must abort planning or apply.
        let path = marks
            .directory
            .as_ref()
            .expect("component directory")
            .path()
            .join("objects.sqlite3");
        let connection = crucible_cas::content_store::fixture_sqlite_heap()
            .expect("authored SQLite fixture process")
            .open_connection(path, rusqlite::OpenFlags::default())
            .expect("mutation connection");
        connection
            .execute("DELETE FROM objects", [])
            .expect("simulate storage loss");
        assert!(marks.contains(&id).is_err());
        let account = mark_account(&marks.original).expect("same mark child");
        let other = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"other page");
        assert!(
            marks
                .map
                .insert_batch_with_boundary(
                    marks.root.content_id(),
                    &[(mark_key(other), other)],
                    &account,
                    &mut || Ok(()),
                )
                .is_err()
        );
    }
}
