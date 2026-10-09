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

// One prepaid page survives graph traversal; no complete RAM closure is stored
// in memory. A batch root becomes authoritative only after checked publication
// and the same operation's final refusal check both succeed.
struct PendingMarks {
    entries: Vec<(CampaignHash, ContentId)>,
    _credit: crucible_cas::owned_decode::ResourceLoan,
}

impl PendingMarks {
    fn new(operation: &CampaignGcOperationContext<'_>) -> Result<Self, StoreError> {
        let credit = operation
            .reserve_array::<(CampaignHash, ContentId)>(MerkleMap::MAX_CHECKED_BATCH_UPSERTS)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(MerkleMap::MAX_CHECKED_BATCH_UPSERTS)
            .map_err(|source| StoreError::StreamIo {
                operation: "allocate bounded GC mark page",
                source: io::Error::other(source),
            })?;
        Ok(Self {
            entries,
            _credit: credit,
        })
    }

    fn insert(
        &mut self,
        marks: &mut Reachability,
        id: ContentId,
        operation: &CampaignGcOperationContext<'_>,
    ) -> Result<(), StoreError> {
        operation.check()?;
        self.entries.push((mark_key(id), id));
        if self.entries.len() == MerkleMap::MAX_CHECKED_BATCH_UPSERTS {
            self.flush(marks, operation)?;
        }
        Ok(())
    }

    fn flush(
        &mut self,
        marks: &mut Reachability,
        operation: &CampaignGcOperationContext<'_>,
    ) -> Result<(), StoreError> {
        if self.entries.is_empty() {
            return Ok(());
        }
        operation.check()?;
        self.entries.sort_unstable_by_key(|entry| entry.0);
        if self
            .entries
            .windows(2)
            .any(|pair| pair[0].0 == pair[1].0 && pair[0].1 != pair[1].1)
        {
            return Err(StoreError::Corrupt {
                id: marks.root.content_id(),
            });
        }
        self.entries.dedup_by_key(|entry| entry.0);
        let account = mark_account(&marks.original)?;
        let root = marks
            .map
            .insert_batch_with_boundary(
                marks.root.content_id(),
                &self.entries,
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
        self.entries.clear();
        Ok(())
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
