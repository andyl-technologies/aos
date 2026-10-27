//! Resolves actual missing metadata through currently eligible verified containers.
//!
//! The current merged row and sticky quarantine remain authoritative. Recovery
//! runs only after observing physical absence, never after corruption. Every
//! examined index and missing object remains in the held operation's read ledger;
//! no inventory entry, decoded member or prior restoration grants authority.

use super::{
    BucketBinding, BucketKey, CachedMetadataPack, Clock, ContentValidator, Identity, LocalFs,
    MetadataStore, PackClass, PackId, PackIndexSnapshot, PackReader, RecordRead, StoreFailure,
    TERRANE_V1, corrupt, unsupported,
};
use crate::{bucket::catalog::Catalog, pack::IndexEntry};
use terrane_format::identity::IdentityKind;

impl<F, B, V> MetadataStore<'_, '_, F, B, V>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    /// Finds an eligible duplicate after actual loss without changing placement rows.
    ///
    /// Scans only the complete selected inventory, excludes active exclusions,
    /// permanent burns and tombstoned containers, and opens no Data pack body.
    /// A present corrupt index or pack fails closed rather than selecting another
    /// copy. Requested-member checks still run in the caller after acquisition.
    ///
    /// # Errors
    /// Refuses incomplete inventory, changed sessions, malformed or corrupt
    /// containers, failed retained reads and the absence of an eligible member.
    pub(super) async fn recover_missing_metadata(
        &self,
        catalog: &Catalog,
        identity: &Identity,
        missing: PackId,
    ) -> Result<(PackId, IndexEntry, CachedMetadataPack), StoreFailure> {
        let hash = identity.terrane_v1_digest().map_err(|_| corrupt())?;
        for inventory in catalog.inventory.as_ref().ok_or_else(unsupported)? {
            self.session.recheck()?;
            let id = PackId::from_random_bytes(inventory.pack_id);
            if id == missing
                || self
                    .held
                    .bucket()
                    .physically_excluded(catalog, id.as_bytes())
            {
                continue;
            }
            let Some((index, snapshot)) = self.read_metadata_index(catalog, id).await? else {
                continue;
            };
            self.reads.lock().map_err(|_| corrupt())?.push(index);
            if snapshot.header().class() != PackClass::Meta {
                continue;
            }
            let Some(entry) = snapshot.entries().iter().find(|entry| {
                entry.hash() == &hash && entry.kind().identity_kind() == identity.kind()
            }) else {
                continue;
            };
            if let Some(container) = self.read_metadata_pack(catalog, id).await? {
                return Ok((id, entry.clone(), container));
            }
        }
        Err(corrupt())
    }

    /// Acquires a checked metadata container or retains observed physical absence.
    ///
    /// # Errors
    /// Refuses malformed or corrupt inventory, indexes and containers, Data
    /// class, failed native reads and poisoned read-ledger synchronization.
    pub(super) async fn read_metadata_pack(
        &self,
        catalog: &Catalog,
        id: PackId,
    ) -> Result<Option<CachedMetadataPack>, StoreFailure> {
        let Some((index, snapshot)) = self.read_metadata_index(catalog, id).await? else {
            return Ok(None);
        };
        if snapshot.header().class() != PackClass::Meta {
            return Err(corrupt());
        }
        let inventory = catalog
            .inventory
            .as_ref()
            .and_then(|entries| entries.iter().find(|entry| entry.pack_id == *id.as_bytes()))
            .ok_or_else(corrupt)?;
        let pack = self
            .held
            .bucket()
            .read_optional_observed(&BucketKey::parse(&id.pack_key()).map_err(|_| corrupt())?)
            .await?;
        let Some(bytes) = pack.bytes() else {
            self.reads
                .lock()
                .map_err(|_| corrupt())?
                .extend([index, pack]);
            return Ok(None);
        };
        if bytes.len() as u64 != inventory.pack_size {
            return Err(corrupt());
        }
        let identity = TERRANE_V1
            .from_digest(IdentityKind::Pack, &inventory.pack_hash)
            .map_err(|_| corrupt())?;
        TERRANE_V1.verify(&identity, bytes).map_err(|_| corrupt())?;
        let reader = PackReader::open(bytes).map_err(|_| corrupt())?;
        reader
            .check_index_object(index.bytes().ok_or_else(corrupt)?)
            .map_err(|_| corrupt())?;
        Ok(Some(CachedMetadataPack {
            inventory: inventory.clone(),
            index,
            pack,
        }))
    }

    async fn read_metadata_index(
        &self,
        catalog: &Catalog,
        id: PackId,
    ) -> Result<Option<(RecordRead, PackIndexSnapshot)>, StoreFailure> {
        let index = self
            .held
            .bucket()
            .read_optional_observed(&BucketKey::parse(&id.index_key()).map_err(|_| corrupt())?)
            .await?;
        let Some(bytes) = index.bytes() else {
            self.reads.lock().map_err(|_| corrupt())?.push(index);
            return Ok(None);
        };
        let snapshot =
            PackIndexSnapshot::decode(bytes, catalog.capabilities.generation.ok_or_else(corrupt)?)
                .map_err(|_| corrupt())?;
        let inventory = catalog
            .inventory
            .as_ref()
            .and_then(|entries| entries.iter().find(|entry| entry.pack_id == *id.as_bytes()))
            .ok_or_else(corrupt)?;
        if snapshot.header().id() != id || bytes.len() as u64 != inventory.index_size {
            return Err(corrupt());
        }
        let identity = TERRANE_V1
            .from_digest(IdentityKind::Index, &inventory.index_hash)
            .map_err(|_| corrupt())?;
        TERRANE_V1.verify(&identity, bytes).map_err(|_| corrupt())?;
        Ok(Some((index, snapshot)))
    }
}
