//! Observes selected container metadata and detached indexes without data bodies.
//!
//! Complete catalog data and physical metadata remain observations. They cannot
//! construct a current collection carrier or authorize a retirement effect.

use super::{MetadataStore, corrupt, record, unsupported};
use crate::bucket::BucketBinding;
use crate::bucket::publication::receipts::GcPackRead;
use crate::pack::{MergedShard, PackId, PackIndexSnapshot};
use crate::store::{Clock, ContentValidator, LocalFs, StoreFailure};
use std::sync::Arc;
use terrane_format::bucket::{BucketCapabilities, BucketKey, PackExclusion, PackInventoryEntry};
use terrane_format::identity::{IdentityKind, TERRANE_V1};

/// Retains complete selected catalog data while preserving its exact logical binding.
pub(crate) struct CollectionCatalog {
    catalog: Arc<crate::bucket::catalog::Catalog>,
    manifest: Vec<u8>,
}

impl CollectionCatalog {
    /// Borrows the actual selected capabilities and generation pointer.
    pub(crate) fn capabilities(&self) -> &BucketCapabilities {
        &self.catalog.capabilities
    }

    /// Borrows exact selected capability bytes for conditional publication.
    pub(crate) fn capability_bytes(&self) -> &[u8] {
        &self.catalog.capability_bytes
    }

    /// Borrows exact verified generation shards.
    pub(crate) fn shards(&self) -> &[MergedShard] {
        &self.catalog.shards
    }

    /// Borrows the complete inventory, refusing legacy unknown completeness.
    ///
    /// # Errors
    /// Refuses missing inventory rather than treating it as an empty catalog.
    pub(crate) fn inventory(&self) -> Result<&[PackInventoryEntry], StoreFailure> {
        self.catalog.inventory.as_deref().ok_or_else(unsupported)
    }

    /// Borrows complete active physical exclusion incarnations.
    ///
    /// # Errors
    /// Refuses unknown exclusion completeness.
    pub(crate) fn exclusions(&self) -> Result<&[PackExclusion], StoreFailure> {
        self.catalog.exclusions.as_deref().ok_or_else(unsupported)
    }

    /// Borrows complete permanently unavailable pack IDs.
    ///
    /// # Errors
    /// Refuses unknown permanent-burn completeness.
    pub(crate) fn burns(&self) -> Result<&[[u8; 16]], StoreFailure> {
        self.catalog.burns.as_deref().ok_or_else(unsupported)
    }
}

impl<F, B, V> MetadataStore<'_, '_, F, B, V>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    /// Observes a complete catalog from the actual held selected generation.
    ///
    /// # Errors
    /// Refuses unknown inventory, exclusions or burns and unavailable metadata.
    pub(crate) async fn collection_catalog(&self) -> Result<CollectionCatalog, StoreFailure> {
        self.session.recheck()?;
        let catalog = self.catalog().await?;
        if catalog.inventory.is_none() || catalog.exclusions.is_none() || catalog.burns.is_none() {
            return Err(unsupported());
        }
        let generation = catalog.capabilities.generation.ok_or_else(corrupt)?;
        let manifest = self
            .selected
            .get(&format!("objects/index/{generation}/MANIFEST"))
            .and_then(Option::as_ref)
            .ok_or_else(corrupt)?
            .clone();
        self.session.recheck()?;
        Ok(CollectionCatalog { catalog, manifest })
    }

    /// Reads an inventory-bound detached index and observes the actual pack metadata.
    ///
    /// Neither data nor meta pack bodies are opened by this operation. Backend
    /// age and incarnation still need independent retained-descriptor fencing.
    ///
    /// # Errors
    /// Rejects a different selected catalog, absent inventory members, unsafe
    /// pack nodes, mismatched hash/size/index bindings and overflowing bounds.
    pub(crate) async fn pack_index(
        &self,
        catalog: &CollectionCatalog,
        pack: PackId,
    ) -> Result<GcPackRead, StoreFailure> {
        self.session.recheck()?;
        let generation = catalog.capabilities().generation.ok_or_else(corrupt)?;
        if self.selected.get("CAPABILITIES").and_then(Option::as_deref)
            != Some(catalog.capability_bytes())
            || self
                .selected
                .get(&format!("objects/index/{generation}/MANIFEST"))
                .and_then(Option::as_deref)
                != Some(catalog.manifest.as_slice())
        {
            return Err(corrupt());
        }
        let inventory = catalog
            .inventory()?
            .iter()
            .find(|entry| entry.pack_id == *pack.as_bytes())
            .ok_or_else(corrupt)?
            .clone();
        let index = record(self.held, &pack.index_key()).await?;
        let bytes = index.bytes().ok_or_else(corrupt)?;
        let identity = TERRANE_V1
            .from_digest(IdentityKind::Index, &inventory.index_hash)
            .map_err(|_| corrupt())?;
        if bytes.len() as u64 != inventory.index_size {
            return Err(corrupt());
        }
        TERRANE_V1.verify(&identity, bytes).map_err(|_| corrupt())?;
        let snapshot = PackIndexSnapshot::decode(bytes, generation).map_err(|_| corrupt())?;
        if snapshot.header().id() != pack {
            return Err(corrupt());
        }

        let bucket = self.held.bucket();
        let key = BucketKey::parse(&pack.pack_key()).map_err(|_| corrupt())?;
        bucket.check_payload_namespace(&key).await?;
        let pack_path = bucket.path(&key);
        let metadata = bucket
            .inner
            .fs
            .symlink_metadata(&pack_path)
            .await
            .map_err(crate::bucket::files::io_failure)?;
        let owner = bucket.publication_operator_uid().ok_or_else(unsupported)?;
        check_pack_metadata(&metadata, owner)?;
        check_pack_metadata(index.metadata().ok_or_else(corrupt)?, owner)?;
        if metadata.len() != inventory.pack_size {
            return Err(corrupt());
        }
        let body_end = inventory
            .pack_size
            .checked_sub(inventory.index_size)
            .and_then(|size| size.checked_add(terrane_format::pack_format::HEADER_SIZE as u64))
            .and_then(|size| size.checked_sub(terrane_format::pack_format::FOOTER_SIZE as u64))
            .ok_or_else(corrupt)?;
        if snapshot.entries().iter().any(|entry| {
            entry
                .offset()
                .checked_add(u64::from(entry.body_len()))
                .is_none_or(|end| end > body_end)
        }) {
            return Err(corrupt());
        }
        self.session.recheck()?;
        self.reads
            .lock()
            .map_err(|_| corrupt())?
            .push(index.clone());
        Ok(GcPackRead::observed(
            inventory, pack_path, metadata, index, snapshot,
        ))
    }
}

#[cfg(unix)]
fn check_pack_metadata(metadata: &std::fs::Metadata, owner: u32) -> Result<(), StoreFailure> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
    {
        return Err(corrupt());
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_pack_metadata(_metadata: &std::fs::Metadata, _owner: u32) -> Result<(), StoreFailure> {
    Err(unsupported())
}
