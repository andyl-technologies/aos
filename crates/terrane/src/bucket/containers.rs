//! Publishes whole pack containers without implicitly admitting their members.
//!
//! A whole-pack upload admits only its named pack and detached-index identities.
//! Every member is verified, but exact live-body shards remain unchanged. This
//! preserves quarantine tombstones; individual bodies need independent admission.

use super::catalog::{Catalog, registered};
use super::content::{corrupt, invalid};
use super::{BucketBinding, FileBucket, files};
use crate::pack::{EntryKind, MergedShard, NativeBodyDecoder, PackId, PackReader};
use crate::store::{Clock, ContentValidator, LocalFs, MetaUpload, StoreFailure};
use std::collections::{BTreeMap, BTreeSet};
use terrane_core::bucket::PackInventoryEntry;
use terrane_core::codec::{Codec, parse_envelope};
use terrane_core::identity::{Identity, IdentityKind, TERRANE_V1};

/// Computes the immutable identity and size bindings of a sealed container pair.
///
/// # Errors
/// Rejects artifacts outside the initial registered identity profile.
pub(super) fn inventory_entry(
    id: PackId,
    pack: &[u8],
    index: &[u8],
) -> Result<PackInventoryEntry, StoreFailure> {
    let pack_hash = TERRANE_V1
        .calculate(IdentityKind::Pack, pack)
        .map_err(|_| files::malformed())?
        .terrane_v1_digest()
        .map_err(|_| files::malformed())?;
    let index_hash = TERRANE_V1
        .calculate(IdentityKind::Index, index)
        .map_err(|_| files::malformed())?
        .terrane_v1_digest()
        .map_err(|_| files::malformed())?;
    Ok(PackInventoryEntry {
        pack_id: *id.as_bytes(),
        pack_hash,
        pack_size: pack.len() as u64,
        index_hash,
        index_size: index.len() as u64,
    })
}

impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    FileBucket<F, C, V>
{
    /// Verifies both retained artifacts against their authoritative inventory row.
    ///
    /// # Errors
    /// Returns corruption for missing or mismatched bytes, pack IDs, or detached
    /// indexes, and propagates failed filesystem reads.
    pub(super) async fn verified_container(
        &self,
        entry: &PackInventoryEntry,
    ) -> Result<(Vec<u8>, Vec<u8>), StoreFailure> {
        let id = PackId::from_random_bytes(entry.pack_id);
        let identity = TERRANE_V1
            .from_digest(IdentityKind::Pack, &entry.pack_hash)
            .map_err(|_| files::layout_corrupt())?;
        let pack = self
            .read_optional(&registered(&id.pack_key())?)
            .await?
            .ok_or_else(|| corrupt(&identity))?;
        let index = self
            .read_optional(&registered(&id.index_key())?)
            .await?
            .ok_or_else(|| corrupt(&identity))?;
        if pack.len() as u64 != entry.pack_size || index.len() as u64 != entry.index_size {
            return Err(corrupt(&identity));
        }
        TERRANE_V1
            .verify(&identity, &pack)
            .map_err(|_| corrupt(&identity))?;
        let index_identity = TERRANE_V1
            .from_digest(IdentityKind::Index, &entry.index_hash)
            .map_err(|_| corrupt(&identity))?;
        TERRANE_V1
            .verify(&index_identity, &index)
            .map_err(|_| corrupt(&index_identity))?;
        let reader = PackReader::open(&pack).map_err(|_| corrupt(&identity))?;
        if reader.header().id() != id {
            return Err(corrupt(&identity));
        }
        reader
            .check_index_object(&index)
            .map_err(|_| corrupt(&identity))?;
        Ok((pack, index))
    }

    /// Resolves a named container only from the selected inventory.
    ///
    /// # Errors
    /// Rejects incompatible profiles and propagates artifact verification or I/O
    /// failures. Callers check exact tombstones before using the returned bytes.
    pub(super) async fn container(
        &self,
        catalog: &Catalog,
        identity: &Identity,
    ) -> Result<Option<Vec<u8>>, StoreFailure> {
        if identity.profile() != TERRANE_V1.name() {
            return Err(files::malformed());
        }
        if !matches!(identity.kind(), IdentityKind::Pack | IdentityKind::Index) {
            return Ok(None);
        }
        let hash = identity
            .terrane_v1_digest()
            .map_err(|_| files::malformed())?;
        let entry = catalog.inventory.as_ref().and_then(|entries| {
            entries.iter().find(|entry| {
                !self.physically_excluded(catalog, &entry.pack_id)
                    && match identity.kind() {
                        IdentityKind::Pack => entry.pack_hash == hash,
                        IdentityKind::Index => entry.index_hash == hash,
                        _ => false,
                    }
            })
        });
        let Some(entry) = entry else {
            return Ok(None);
        };
        let (pack, index) = self.verified_container(entry).await?;
        Ok(Some(if identity.kind() == IdentityKind::Pack {
            pack
        } else {
            index
        }))
    }

    /// Admits whole-pack and detached-index containers without admitting members.
    ///
    /// Every embedded body is verified before publication. Existing exact live
    /// shards and tombstones are preserved, so an imported manifest becomes
    /// individually visible only after ordinary admission checks its referenced
    /// chunks in their declared final or nonfinal context.
    ///
    /// # Errors
    /// Rejects invalid bodies, metadata, dictionary dependencies, or immutable
    /// artifact collisions, and propagates unavailable durable I/O.
    pub(super) async fn import_pack(
        &self,
        mut catalog: Catalog,
        bytes: &[u8],
        identity: Identity,
    ) -> Result<Identity, StoreFailure> {
        let reader = PackReader::open(bytes).map_err(|_| invalid("PACK-10"))?;
        if self.physically_excluded(&catalog, reader.header().id().as_bytes()) {
            return Err(StoreFailure::new(crate::store::StoreErrorKind::Absent(
                identity,
            )));
        }
        let mut dictionaries = BTreeMap::new();
        let mut pending: Vec<_> = reader.entries().iter().collect();
        while !pending.is_empty() {
            let mut remaining = Vec::new();
            for entry in &pending {
                let start = usize::try_from(entry.offset()).map_err(|_| invalid("PACK-3"))?;
                let end = start
                    .checked_add(entry.body_len() as usize)
                    .ok_or_else(|| invalid("PACK-3"))?;
                let body = bytes.get(start..end).ok_or_else(|| invalid("PACK-3"))?;
                if entry.kind() == EntryKind::Chunk
                    && let Codec::ZstdDictionary(hash) =
                        parse_envelope(body).map_err(|_| invalid("CDC-7"))?.codec
                    && let std::collections::btree_map::Entry::Vacant(dictionary) =
                        dictionaries.entry(hash)
                {
                    if reader
                        .entries()
                        .iter()
                        .any(|entry| entry.kind() == EntryKind::Chunk && entry.hash() == &hash)
                    {
                        remaining.push(*entry);
                        continue;
                    }

                    dictionary.insert(self.dictionary_plaintext(&catalog, &hash).await?);
                }
                let decoder =
                    NativeBodyDecoder::new(&self.inner.config.chunk_profile, &dictionaries);
                let plaintext = reader
                    .read(entry.kind(), entry.hash(), &decoder)
                    .map_err(|_| invalid("STORE-33"))?;
                if entry.kind() == EntryKind::Chunk {
                    dictionaries.insert(*entry.hash(), plaintext);
                } else {
                    let upload = MetaUpload::new(entry.kind().identity_kind(), &plaintext)?;
                    self.inner.validator.validate_meta(&upload)?;
                }
            }
            if remaining.len() == pending.len() {
                return Err(invalid("CDC-9"));
            }
            pending = remaining;
        }
        if catalog.inventory.as_ref().is_some_and(|entries| {
            entries
                .iter()
                .any(|entry| entry.pack_hash == identity.digest())
        }) {
            return Ok(identity);
        }

        let id = reader.header().id();
        let index = reader.index_object();
        let entry = inventory_entry(id, bytes, &index)?;
        self.immutable(&registered(&id.pack_key())?, bytes).await?;
        self.immutable(&registered(&id.index_key())?, &index)
            .await?;
        self.verified_container(&entry).await?;
        self.add_inventory(&mut catalog, entry)?;

        let generation = self.next_generation(&catalog).await?;
        let mut shards = Vec::new();
        for previous in &catalog.shards {
            shards.push(
                MergedShard::decode(&previous.encode(), generation, previous.shard())
                    .map_err(|_| files::layout_corrupt())?,
            );
        }
        if shards.first().is_none_or(|shard| shard.shard() != 0) {
            let empty =
                MergedShard::rebuild(0, generation, &[], &BTreeSet::new(), None, &BTreeSet::new())
                    .map_err(|_| files::layout_corrupt())?;
            shards.insert(0, empty);
        }
        self.publish_shards(catalog, generation, &shards).await?;
        Ok(identity)
    }
}
