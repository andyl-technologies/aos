//! Disk-backed membership for authenticated GC marking.
//!
//! A temporary SQLite CAS owns the potentially large RAM graph's mark tree.
//! A retained Merkle root authenticates every membership lookup. Planning and
//! apply use the same authenticated traversal under their ref inventory fence;
//! storage failure aborts the operation before any deletion is admitted.

use std::io;
use std::sync::Arc;

use crucible_campaign::{
    CampaignHash, CampaignRepository, MAX_CAMPAIGN_CLOSURE_OBJECTS, MerkleMap, MerkleMapRoot,
};
use crucible_cas::content_store::{
    ContentId, DurabilityRequirement, RefInventoryFence, SqliteBlobBackend, StoreError,
};
use crucible_cas::ram::{RamStore, RamStoreLimits};

pub(super) struct Reachability {
    map: MerkleMap,
    root: MerkleMapRoot,
    directory: tempfile::TempDir,
}

impl Reachability {
    pub(super) fn authenticate(
        repository: &CampaignRepository,
        roots: impl IntoIterator<Item = ContentId>,
        direct: impl IntoIterator<Item = ContentId>,
        inventory: &dyn RefInventoryFence,
    ) -> Result<Self, StoreError> {
        let mut marks = Self::new()?;
        let closure = repository
            .authenticated_storage_closure(roots, inventory)
            .map_err(|error| marks.failure("authenticate GC closure", error))?;
        for id in closure.objects().iter().copied().chain(direct) {
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
                marks.insert(id).map_err(Into::into)
            })
            .map_err(|error| marks.failure("authenticate GC RAM graph", error))?;
        }
        Ok(marks)
    }

    fn new() -> Result<Self, StoreError> {
        let directory = tempfile::tempdir().map_err(|source| StoreError::Io {
            operation: "create GC mark directory",
            path: std::env::temp_dir(),
            source,
        })?;
        let backend = Arc::new(SqliteBlobBackend::open("gc-marks", directory.path())?);
        let map = MerkleMap::new(backend);
        let root = map.empty().map_err(|source| StoreError::Io {
            operation: "initialize GC mark tree",
            path: directory.path().to_owned(),
            source: io::Error::other(source),
        })?;
        Ok(Self {
            map,
            root,
            directory,
        })
    }

    fn insert(&mut self, id: ContentId) -> Result<(), StoreError> {
        // Keeping the immutable root in memory authenticates both presence and
        // absence. A damaged SQLite row must never turn a reachable object into
        // an apparently absent mark that could authorize deletion.
        let root = self
            .map
            .insert(self.root.content_id(), mark_key(id), id)
            .map_err(|source| self.failure("insert GC mark", source))?;
        if root.entry_count() > MAX_CAMPAIGN_CLOSURE_OBJECTS as u64 {
            return Err(StoreError::Quota);
        }
        self.root = root;
        Ok(())
    }

    pub(super) fn contains(&self, id: &ContentId) -> Result<bool, StoreError> {
        let value = self
            .map
            .get(self.root.content_id(), mark_key(*id))
            .map_err(|source| self.failure("authenticate GC mark", source))?;
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
        StoreError::Io {
            operation,
            path: self.directory.path().to_owned(),
            source: io::Error::other(source),
        }
    }
}

fn mark_key(id: ContentId) -> CampaignHash {
    CampaignHash::derive("crucible.gc.typed-mark.v1", id.to_string().as_bytes())
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
        let path = marks.directory.path().join("objects.sqlite3");
        let connection = rusqlite::Connection::open(path).expect("mutation connection");
        connection
            .execute("DELETE FROM objects", [])
            .expect("simulate storage loss");
        assert!(marks.contains(&id).is_err());
    }
}
