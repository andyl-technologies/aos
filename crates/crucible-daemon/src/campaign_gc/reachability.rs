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
    StorePhysicalQuotaGuard,
};
use crucible_cas::owned_decode::DecodeBudget;
use crucible_cas::ram::{RamStore, RamStoreError, RamStoreLimits};

use super::CampaignGcOperationContext;

#[cfg(test)]
mod metadata_lifecycle;

pub(super) struct Reachability {
    map: MerkleMap,
    root: MerkleMapRoot,
    #[cfg(test)]
    directory: Option<tempfile::TempDir>,
    resources: Arc<dyn StorePhysicalQuotaGuard>,
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
        let mut marks = Self::with_backend(operation.marks())?;
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
            marks.insert(id)?;
        }

        if closure.ram_roots().is_empty() {
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
            ram.visit_inventory_graph(*root, inventory, &mut |id| {
                operation.check()?;
                marks.insert(id).map_err(Into::into)
            })
            .map_err(|error| match error {
                RamStoreError::Store(source) => source,
                other => marks.failure("authenticate GC RAM graph", other),
            })?;
        }
        Ok(marks)
    }

    fn with_backend(backend: Arc<dyn ImmutableBlobBackend>) -> Result<Self, StoreError> {
        let resources = backend.metadata_resources()?;
        let account = mark_account(&resources)?;
        let _scope = account.enter();
        let map = MerkleMap::new(backend);
        let root = map.empty().map_err(|source| StoreError::StreamIo {
            operation: "initialize GC mark tree",
            source: io::Error::other(source),
        })?;
        account.check().map_err(mark_admission)?;
        Ok(Self {
            map,
            root,
            #[cfg(test)]
            directory: None,
            resources,
        })
    }

    #[cfg(test)]
    fn new() -> Result<Self, StoreError> {
        use crate::exact_checkpoint_store::test_support::{
            fixture_metadata_backend, fixture_ram_root_resources,
        };

        let directory = tempfile::tempdir().map_err(|source| StoreError::Io {
            operation: "create component GC mark directory",
            path: std::env::temp_dir(),
            source,
        })?;
        let resources = fixture_ram_root_resources().map_err(|source| StoreError::Supervision {
            source: Box::new(source),
        })?;
        let backend = fixture_metadata_backend(
            Arc::new(crucible_cas::content_store::SqliteBlobBackend::open(
                "component-gc-marks",
                directory.path(),
            )?),
            resources,
        );
        let mut marks = Self::with_backend(backend)?;
        marks.directory = Some(directory);
        Ok(marks)
    }

    fn insert(&mut self, id: ContentId) -> Result<(), StoreError> {
        let account = mark_account(&self.resources)?;
        let _scope = account.enter();
        // Keeping the immutable root in memory authenticates both presence and
        // absence. A damaged SQLite row must never turn a reachable object into
        // an apparently absent mark that could authorize deletion.
        let root = self
            .map
            .insert(self.root.content_id(), mark_key(id), id)
            .map_err(|source| self.failure("insert GC mark", source))?;
        account.check().map_err(mark_admission)?;
        if root.entry_count() > MAX_CAMPAIGN_CLOSURE_OBJECTS as u64 {
            return Err(StoreError::Quota);
        }
        self.root = root;
        Ok(())
    }

    pub(super) fn contains(&self, id: &ContentId) -> Result<bool, StoreError> {
        let account = mark_account(&self.resources)?;
        let _scope = account.enter();
        let value = self
            .map
            .get(self.root.content_id(), mark_key(*id))
            .map_err(|source| self.failure("authenticate GC mark", source))?;
        account.check().map_err(mark_admission)?;
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

// Mark operations return only scalar identities. Their decoded nodes, source
// handles and publication buffers close before this child account; immutable
// backend copies retain their own original-account custody independently.
fn mark_account(resources: &Arc<dyn StorePhysicalQuotaGuard>) -> Result<DecodeBudget, StoreError> {
    if let Some(account) =
        crucible_cas::owned_decode::current_child_budget().map_err(mark_admission)?
    {
        return Ok(account);
    }
    DecodeBudget::for_store(Arc::clone(resources)).map_err(mark_admission)
}

fn mark_admission(source: crucible_cas::owned_decode::DecodeAdmissionError) -> StoreError {
    StoreError::Supervision {
        source: Box::new(source),
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
        let connection = rusqlite::Connection::open(path).expect("mutation connection");
        connection
            .execute("DELETE FROM objects", [])
            .expect("simulate storage loss");
        assert!(marks.contains(&id).is_err());
    }
}
