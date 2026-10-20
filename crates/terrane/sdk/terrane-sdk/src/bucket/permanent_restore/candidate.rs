//! Verifies collector-only source content before constructing a fresh placement.
//!
//! Source extraction retains descriptors but grants no membership. This producer
//! separately verifies every body and metadata dependency under the current
//! selected catalog; permanent source names never become ordinary read routes.

use super::super::{BucketBinding, containers, files, held::HeldBucket};
use crate::pack::{EntryKind, NativeBodyDecoder, PackId, PackReader, PackWriter};
use crate::selected_bridge::native_permanent_local::CheckedPermanentLocalOwner;
use crate::store::native_publication_effects::collection_permanent_local::NativePermanentObservation;
use crate::store::{ChunkPosition, Clock, ContentValidator, LocalFs, MetaUpload, StoreFailure};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use terrane_format::codec::{Codec, parse_envelope};
use terrane_format::identity::{IdentityKind, TERRANE_V1};

/// Carries verified proposed artifacts and every physical dependency, not admission.
pub(crate) struct Candidate {
    artifacts: containers::ContainerArtifacts,
    source: Arc<NativePermanentObservation>,
    reads: Vec<super::RecordRead>,
    changes: Vec<terrane_format::gc::publication::LogicalChange>,
}

impl Candidate {
    /// Borrows the exact verified backend catalog proposal.
    pub(crate) fn changes(&self) -> &[terrane_format::gc::publication::LogicalChange] {
        &self.changes
    }

    /// Borrows freshly encoded, still unpublished artifacts.
    pub(crate) fn artifacts(&self) -> &containers::ContainerArtifacts {
        &self.artifacts
    }

    /// Borrows the actual extraction descriptor hold.
    pub(crate) fn source(&self) -> &Arc<NativePermanentObservation> {
        &self.source
    }

    /// Borrows complete current serving-container dependency preimages.
    pub(crate) fn reads(&self) -> &[super::RecordRead] {
        &self.reads
    }
}

/// Completes actual staging, backend validation and retained native selection.
///
/// # Errors
/// Refuses incomplete qualification, changed current inputs, any staging or
/// selected successor failure and absent real native durability acknowledgment.
pub(crate) async fn admit<F, B, V>(
    held: &HeldBucket<'_, F, B, V, true>,
    owner: &CheckedPermanentLocalOwner<'_, '_>,
    source: Arc<NativePermanentObservation>,
) -> Result<crate::pack::PackId, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    let candidate = qualify(held, owner, source).await?;
    let staged =
        crate::store::native_publication_effects::collection_permanent_local::stage_candidate(
            held.fs(),
            owner,
            &candidate,
        )
        .await?;
    let mutation = held
        .prepare_raw(owner.observed(), candidate.changes.clone())
        .await?;
    owner.revalidate().await?;
    crate::store::native_publication_effects::collection_permanent_local::publish_candidate(
        held.fs(),
        owner,
        &candidate,
        &mutation,
        staged,
    )
    .await?;
    Ok(candidate.artifacts().id())
}

/// Verifies an actual owned extraction and generates a new secure placement.
///
/// # Errors
/// Refuses mismatched holders, changed source or current owner, incomplete
/// dependencies, invalid content, secure-ID collisions and filesystem failures.
pub(crate) async fn qualify<F, B, V>(
    held: &HeldBucket<'_, F, B, V, true>,
    owner: &CheckedPermanentLocalOwner<'_, '_>,
    source: Arc<NativePermanentObservation>,
) -> Result<Candidate, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    let corrupt = super::super::publication::corrupt;
    owner.revalidate().await?;
    if held.root() != owner.observed().identity().root()
        || held.physical_identity() != owner.observed().identity().physical_identity()
        || source.pack() != owner.pack()
    {
        return Err(corrupt());
    }
    let operation = owner
        .observed()
        .logical()
        .get(owner.key())
        .and_then(Option::as_deref)
        .ok_or_else(corrupt)?;
    if !source.matches_selected(held.root(), owner.backend_control(), owner.key(), operation) {
        return Err(corrupt());
    }
    source
        .recheck_source()
        .map_err(crate::selected_bridge::native_restore_failure)?;
    let extracted = source.extraction().ok_or_else(corrupt)?;
    let reader = PackReader::open(extracted.pack().0).map_err(|_| corrupt())?;
    if reader.header().id().as_bytes() != &owner.pack() {
        return Err(corrupt());
    }
    reader
        .check_index_object(extracted.index().0)
        .map_err(|_| corrupt())?;

    let bucket = held.bucket();
    let catalog = bucket.catalog_observed(owner.observed()).await?;
    let mut reads = Vec::new();
    // Whole serving-container receipts cover dictionary and metadata dependency
    // reads. Excluded P remains accessible only through the extraction above.
    let inventory = catalog.inventory.as_ref().ok_or_else(corrupt)?;
    let mut containers = BTreeSet::new();
    containers.extend(inventory.iter().map(|row| row.pack_id));
    for row in catalog
        .shards
        .iter()
        .flat_map(crate::pack::MergedShard::entries)
    {
        if row.state() == crate::pack::RecordState::Live {
            containers.insert(*row.pack().as_bytes());
        }
    }
    for pack in containers {
        if bucket.physically_excluded(&catalog, &pack) {
            continue;
        }
        let id = PackId::from_random_bytes(pack);
        for key in [id.pack_key(), id.index_key()] {
            let key = terrane_format::bucket::BucketKey::parse(&key).map_err(|_| corrupt())?;
            let read = bucket.read_optional_observed(&key).await?;
            if read.bytes().is_none() {
                return Err(corrupt());
            }
            reads.push(read);
        }
        if let Some(inventory) = inventory.iter().find(|row| row.pack_id == pack) {
            let actual = bucket.verified_container(inventory).await?;
            let pair = reads
                .get(reads.len().saturating_sub(2)..)
                .ok_or_else(corrupt)?;
            if pair.len() != 2
                || pair[0].bytes() != Some(actual.0.as_slice())
                || pair[1].bytes() != Some(actual.1.as_slice())
            {
                return Err(corrupt());
            }
        }
    }

    let mut dictionaries = BTreeMap::new();
    let mut encoded_chunks = BTreeMap::new();
    for entry in reader.entries() {
        if entry.kind() != EntryKind::Chunk {
            continue;
        }
        let start = usize::try_from(entry.offset()).map_err(|_| corrupt())?;
        let end = start
            .checked_add(entry.body_len() as usize)
            .ok_or_else(corrupt)?;
        let body = extracted.pack().0.get(start..end).ok_or_else(corrupt)?;
        encoded_chunks.insert(*entry.hash(), body);
    }
    let mut pending = std::collections::BTreeSet::new();
    for encoded in encoded_chunks.values() {
        if let Codec::ZstdDictionary(hash) = parse_envelope(encoded).map_err(|_| corrupt())?.codec {
            pending.insert(hash);
        }
    }
    // Resolve source-contained dictionary chains without routing a burned source
    // through ordinary get. Current external dictionaries retain serving receipts.
    while !pending.is_empty() {
        let mut progressed = false;
        for hash in pending.clone() {
            let Some(encoded) = encoded_chunks.get(&hash) else {
                dictionaries.insert(hash, bucket.dictionary_plaintext(&catalog, &hash).await?);
                pending.remove(&hash);
                progressed = true;
                continue;
            };
            let dependency = match parse_envelope(encoded).map_err(|_| corrupt())?.codec {
                Codec::ZstdDictionary(hash) => Some(hash),
                _ => None,
            };
            if let Some(dependency) = dependency
                && !dictionaries.contains_key(&dependency)
            {
                if pending.insert(dependency) {
                    progressed = true;
                }
                continue;
            }
            let entry = reader
                .entries()
                .iter()
                .find(|entry| entry.kind() == EntryKind::Chunk && entry.hash() == &hash)
                .ok_or_else(corrupt)?;
            let identity = TERRANE_V1
                .from_digest(IdentityKind::Chunk, &hash)
                .map_err(|_| corrupt())?;
            let plaintext = crate::codec::decode_verified(
                encoded,
                entry.plaintext_len() as usize,
                &bucket.inner.config.chunk_profile,
                true,
                &identity,
                dependency
                    .and_then(|hash| dictionaries.get(&hash))
                    .map(Vec::as_slice),
            )
            .map_err(|_| corrupt())?;
            dictionaries.insert(hash, plaintext.plaintext().to_vec());
            pending.remove(&hash);
            progressed = true;
        }
        if !progressed {
            return Err(corrupt());
        }
    }
    let decoder = NativeBodyDecoder::new(&bucket.inner.config.chunk_profile, &dictionaries);
    let admissions = reader
        .verified_admissions(&[], &decoder)
        .map_err(|_| corrupt())?;
    for admission in &admissions {
        if admission.kind == EntryKind::Chunk {
            continue;
        }
        let upload = MetaUpload::new(admission.kind.identity_kind(), &admission.bytes)?;
        bucket.inner.validator.validate_meta(&upload)?;
        for requirement in bucket.inner.validator.chunk_requirements(&upload)? {
            if requirement.identity.kind() != IdentityKind::Chunk
                || requirement.identity.profile() != TERRANE_V1.name()
            {
                return Err(files::malformed());
            }
            let hash = requirement
                .identity
                .terrane_v1_digest()
                .map_err(|_| corrupt())?;
            let current;
            let encoded = match encoded_chunks.get(&hash) {
                Some(encoded) => *encoded,
                None => {
                    current = bucket
                        .verified_body(&catalog, &requirement.identity)
                        .await?;
                    &current
                }
            };
            let dictionary = match parse_envelope(encoded).map_err(|_| corrupt())?.codec {
                Codec::ZstdDictionary(hash) => Some(match dictionaries.get(&hash) {
                    Some(bytes) => bytes.clone(),
                    None => bucket.dictionary_plaintext(&catalog, &hash).await?,
                }),
                _ => None,
            };
            crate::codec::decode_object_chunk_verified(
                encoded,
                requirement.declared_plaintext_len,
                &bucket.inner.config.chunk_profile,
                requirement.position == ChunkPosition::Final,
                &requirement.identity,
                dictionary.as_deref(),
            )
            .map_err(|_| corrupt())?;
        }
    }

    let id = PackId::generate(held.fs())
        .await
        .map_err(files::io_failure)?;
    if id.as_bytes() == &owner.pack()
        || bucket.physically_excluded(&catalog, id.as_bytes())
        || catalog
            .inventory
            .as_ref()
            .is_some_and(|rows| rows.iter().any(|row| row.pack_id == *id.as_bytes()))
    {
        return Err(corrupt());
    }
    let mut writer = PackWriter::new(id, reader.header().class(), false);
    for admission in admissions {
        let actual = if admission.kind == EntryKind::Chunk {
            let encoded = encoded_chunks.get(&admission.hash).ok_or_else(corrupt)?;
            let length = u32::try_from(admission.bytes.len()).map_err(|_| corrupt())?;
            writer
                .append_chunk(admission.hash, encoded, length, 0, &decoder)
                .map_err(|_| corrupt())?;
            admission.hash
        } else {
            writer
                .append_raw(admission.kind, &admission.bytes)
                .map_err(|_| corrupt())?
        };
        if actual != admission.hash {
            return Err(corrupt());
        }
    }
    let sealed = writer.seal().map_err(|_| corrupt())?;
    let artifacts = containers::admitted_artifacts(id, sealed.bytes(), sealed.index_object())?;
    source
        .recheck_source()
        .map_err(crate::selected_bridge::native_restore_failure)?;
    owner.revalidate().await?;
    let changes =
        super::catalog::changes(bucket, owner.observed(), catalog, owner.pack(), &artifacts)?;
    Ok(Candidate {
        changes,
        artifacts,
        source,
        reads,
    })
}
