//! Validates opaque admissions and verifies complete bodies before ranged reads.

#[cfg(all(feature = "tokio", unix))]
pub(in crate::bucket) mod held_nodes;
mod meta_batch;

pub(crate) use meta_batch::BatchOutcome;

use super::catalog::{Catalog, registered};
use super::{BucketBinding, FileBucket, files};
use crate::pack::{
    EntryKind, MergedEntry, NativeBodyDecoder, PackClass, PackId, PackIndexSnapshot, PackReader,
    PackWriter, RecordState,
};
use crate::store::{
    ByteRange, ChunkPosition, ChunkRequirement, Clock, ContentStore, ContentUpload,
    ContentValidator, CorruptSubject, IdentityPrefix, InvalidReason, LocalFs, MetaUpload,
    StoreErrorKind, StoreFailure,
};
use std::collections::{BTreeMap, BTreeSet};
use terrane_core::codec::{Codec, parse_envelope};
use terrane_core::identity::{Identity, IdentityKind, TERRANE_V1};

/// Distinguishes verified bytes from a canonical detached index's excluded pack.
pub(super) enum VerifiedBody {
    /// Contains bytes that passed the complete body verification.
    Bytes(Vec<u8>),
    /// Identifies an otherwise verified detached index naming an excluded pack.
    ExcludedDetachedIndex,
}

pub(super) fn corrupt(identity: &Identity) -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Corrupt(CorruptSubject::Identity(
        identity.clone(),
    )))
}

pub(super) fn invalid(rule_id: &'static str) -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::Upload { rule_id }))
}

fn invalid_chunk(error: crate::codec::FrameError) -> StoreFailure {
    use crate::codec::FrameError;
    use terrane_core::codec::CodecError;

    let rule_id = match &error {
        FrameError::NonfinalChunkTooShort => "CDC-15",
        FrameError::BoundaryMismatch => "CDC-16",
        FrameError::MissingDictionary | FrameError::WrongDictionary => "CDC-9",
        FrameError::WrongIdentityKind | FrameError::Identity(_) => "CDC-14",
        FrameError::ContentSizeMismatch
        | FrameError::PlaintextLengthMismatch
        | FrameError::Envelope(
            CodecError::DeclaredLengthTooLarge | CodecError::RawLengthMismatch,
        ) => "CDC-12",
        FrameError::Envelope(CodecError::CompressedLengthTooLarge) => "CDC-13",
        _ => "CDC-7",
    };
    StoreFailure::with_source(
        StoreErrorKind::Invalid(InvalidReason::Upload { rule_id }),
        error,
    )
}

// Missing or corrupt dependency evidence is an admission failure. Backend
// availability and capability failures retain their closed STORE-7 outcomes.
fn dictionary_admission_failure(error: StoreFailure) -> StoreFailure {
    match error.kind() {
        StoreErrorKind::Absent(_) | StoreErrorKind::Corrupt(_) => StoreFailure::with_source(
            StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: "CDC-9" }),
            error,
        ),
        _ => error,
    }
}

fn dictionary_read_failure(identity: &Identity, error: StoreFailure) -> StoreFailure {
    match error.kind() {
        StoreErrorKind::Absent(_) | StoreErrorKind::Corrupt(_) => StoreFailure::with_source(
            StoreErrorKind::Corrupt(CorruptSubject::Identity(identity.clone())),
            error,
        ),
        _ => error,
    }
}

fn entry_kind(kind: IdentityKind) -> Result<EntryKind, StoreFailure> {
    match kind {
        IdentityKind::Chunk => Ok(EntryKind::Chunk),
        IdentityKind::Manifest => Ok(EntryKind::Manifest),
        IdentityKind::Node => Ok(EntryKind::Node),
        IdentityKind::Commit => Ok(EntryKind::Commit),
        IdentityKind::Bundle => Ok(EntryKind::Bundle),
        IdentityKind::Filter => Ok(EntryKind::Filter),
        IdentityKind::Index => Ok(EntryKind::Index),
        IdentityKind::Attribute => Ok(EntryKind::Attribute),
        IdentityKind::Policy => Ok(EntryKind::Policy),
        IdentityKind::Memo => Ok(EntryKind::Memo),
        IdentityKind::Pack => Err(invalid("STORE-33")),
    }
}

fn empty_chunk() -> Result<Identity, StoreFailure> {
    TERRANE_V1
        .calculate(IdentityKind::Chunk, b"")
        .map_err(|_| files::malformed())
}

impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    FileBucket<F, C, V>
{
    /// Resolves the exact selected unexcluded Live member without reading its body.
    ///
    /// # Errors
    /// Refuses malformed identities and returns absence for unserved placements.
    pub(super) fn location<'a>(
        &self,
        catalog: &'a Catalog,
        identity: &Identity,
    ) -> Result<&'a MergedEntry, StoreFailure> {
        if identity.profile() != TERRANE_V1.name() {
            return Err(files::malformed());
        }
        let hash = identity
            .terrane_v1_digest()
            .map_err(|_| files::malformed())?;
        let kind = entry_kind(identity.kind())?;
        let location = catalog
            .shards
            .iter()
            .find(|shard| shard.shard() == hash[0])
            .and_then(|shard| {
                shard
                    .entries()
                    .binary_search_by_key(&hash, |record| *record.entry().hash())
                    .ok()
                    .map(|position| &shard.entries()[position])
            });
        match location {
            Some(location)
                if location.state() == RecordState::Live
                    && location.entry().kind() == kind
                    && !self.physically_excluded(catalog, location.pack().as_bytes()) =>
            {
                Ok(location)
            }
            _ => Err(StoreFailure::new(StoreErrorKind::Absent(identity.clone()))),
        }
    }

    async fn encoded_body(
        &self,
        catalog: &Catalog,
        identity: &Identity,
    ) -> Result<(Vec<u8>, usize), StoreFailure> {
        let location = self.location(catalog, identity)?;
        let id = location.pack();
        let inventory = catalog
            .inventory
            .as_ref()
            .and_then(|entries| entries.iter().find(|entry| entry.pack_id == *id.as_bytes()));
        let (bytes, index) = if let Some(entry) = inventory {
            self.verified_container(entry).await?
        } else {
            // Optional container inventory does not replace authoritative body
            // membership. Older live placements remain verified below against
            // their exact merged record and detached pack index.
            let bytes = self
                .read_optional(&registered(&id.pack_key())?)
                .await?
                .ok_or_else(|| corrupt(identity))?;
            let index = self
                .read_optional(&registered(&id.index_key())?)
                .await?
                .ok_or_else(|| corrupt(identity))?;
            (bytes, index)
        };
        let reader = PackReader::open(&bytes).map_err(|_| corrupt(identity))?;
        if reader.header().id() != id {
            return Err(corrupt(identity));
        }
        reader
            .check_index_object(&index)
            .map_err(|_| corrupt(identity))?;
        let entry = reader
            .entries()
            .iter()
            .find(|entry| entry.hash() == location.entry().hash())
            .ok_or_else(|| corrupt(identity))?;
        if entry != location.entry() {
            return Err(corrupt(identity));
        }
        let start = usize::try_from(entry.offset()).map_err(|_| corrupt(identity))?;
        let end = start
            .checked_add(entry.body_len() as usize)
            .ok_or_else(|| corrupt(identity))?;
        let encoded = bytes
            .get(start..end)
            .ok_or_else(|| corrupt(identity))?
            .to_vec();
        Ok((encoded, entry.plaintext_len() as usize))
    }

    /// Verifies an entire live identity before exposing any encoded bytes.
    ///
    /// # Errors
    /// Returns typed absence for excluded or unpublished identities, corruption
    /// for invalid persisted bytes, and binding failures when verification cannot
    /// complete. Dictionary chains must be acyclic and independently verified.
    pub(super) async fn verified_body(
        &self,
        catalog: &Catalog,
        identity: &Identity,
    ) -> Result<Vec<u8>, StoreFailure> {
        match self.verified_body_outcome(catalog, identity).await? {
            VerifiedBody::Bytes(bytes) => Ok(bytes),
            VerifiedBody::ExcludedDetachedIndex => {
                Err(StoreFailure::new(StoreErrorKind::Absent(identity.clone())))
            }
        }
    }

    /// Verifies a body while retaining explicit canonical detached-index exclusion.
    ///
    /// # Errors
    /// Preserves absence for missing or excluded content, unknown index policy,
    /// corruption, and unavailable reads. Only a fully verified detached index
    /// naming an excluded pack returns the distinct exclusion outcome.
    pub(super) async fn verified_body_outcome(
        &self,
        catalog: &Catalog,
        identity: &Identity,
    ) -> Result<VerifiedBody, StoreFailure> {
        if identity == &empty_chunk()? {
            return Ok(VerifiedBody::Bytes(vec![0]));
        }
        if self.is_excluded(catalog, identity)? {
            return Err(StoreFailure::new(StoreErrorKind::Absent(identity.clone())));
        }
        if identity.kind() == IdentityKind::Index && !self.index_retirement_known(catalog) {
            // An opaque independently admitted index cannot establish physical
            // retirement completeness. Legacy unknown authority fails closed.
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        if let Some(bytes) = self.container(catalog, identity).await? {
            return Ok(VerifiedBody::Bytes(bytes));
        }
        if identity.kind() == IdentityKind::Pack {
            return Err(StoreFailure::new(StoreErrorKind::Absent(identity.clone())));
        }
        let (encoded, length) = self.encoded_body(catalog, identity).await?;
        if identity.kind() != IdentityKind::Chunk {
            let upload =
                MetaUpload::new(identity.kind(), &encoded).map_err(|_| corrupt(identity))?;
            self.inner
                .validator
                .validate_meta(&upload)
                .map_err(|_| corrupt(identity))?;
            if length != encoded.len() {
                return Err(corrupt(identity));
            }
            TERRANE_V1
                .verify(identity, &encoded)
                .map_err(|_| corrupt(identity))?;
            if identity.kind() == IdentityKind::Index
                && self
                    .detached_index_excluded(catalog, &encoded)
                    .map_err(|_| corrupt(identity))?
            {
                return Ok(VerifiedBody::ExcludedDetachedIndex);
            }
            return Ok(VerifiedBody::Bytes(encoded));
        }

        // Resolve dictionary chains iteratively so hostile envelopes cannot
        // consume the call stack. Each dictionary has its own verified identity.
        let mut seen = BTreeSet::new();
        let mut chain = Vec::new();
        let mut current = identity.clone();
        let mut body = encoded.clone();
        let mut plaintext_len = length;
        loop {
            let hash = current.terrane_v1_digest().map_err(|_| corrupt(identity))?;
            if !seen.insert(hash) {
                return Err(corrupt(identity));
            }
            let envelope = parse_envelope(&body).map_err(|_| corrupt(identity))?;
            let dictionary = match envelope.codec {
                Codec::ZstdDictionary(hash) => Some(hash),
                _ => None,
            };
            chain.push((current, body, plaintext_len));
            let Some(hash) = dictionary else {
                break;
            };
            current = TERRANE_V1
                .from_digest(IdentityKind::Chunk, &hash)
                .map_err(|_| corrupt(identity))?;
            if current == empty_chunk()? {
                body = vec![0];
                plaintext_len = 0;
            } else {
                (body, plaintext_len) = self
                    .encoded_body(catalog, &current)
                    .await
                    .map_err(|error| dictionary_read_failure(identity, error))?;
            }
        }
        let mut dictionary = None;
        for (current, body, plaintext_len) in chain.into_iter().rev() {
            let verified = crate::codec::decode_verified(
                &body,
                plaintext_len,
                &self.inner.config.chunk_profile,
                true,
                &current,
                dictionary.as_deref(),
            )
            .map_err(|_| corrupt(identity))?;
            dictionary = Some(verified.plaintext().to_vec());
        }
        Ok(VerifiedBody::Bytes(encoded))
    }

    /// Resolves a verified dictionary chain without recursive decoder calls.
    ///
    /// # Errors
    /// Rejects missing, cyclic, corrupt, or inadmissible dictionary dependencies.
    pub(super) async fn dictionary_plaintext(
        &self,
        catalog: &Catalog,
        hash: &[u8; 32],
    ) -> Result<Vec<u8>, StoreFailure> {
        let identity = TERRANE_V1
            .from_digest(IdentityKind::Chunk, hash)
            .map_err(|_| invalid("CDC-9"))?;
        let encoded = self
            .verified_body(catalog, &identity)
            .await
            .map_err(dictionary_admission_failure)?;
        // Dictionary chunks may themselves name a dictionary. The chain has
        // already been verified above; decode its authoritative encoded body
        // using the same iterative resolver for plaintext assembly.
        let mut chain = Vec::new();
        let mut current = identity;
        let mut body = encoded;
        loop {
            let length = if current == empty_chunk()? {
                0
            } else {
                self.location(catalog, &current)?.entry().plaintext_len() as usize
            };
            let next = match parse_envelope(&body).map_err(|_| invalid("CDC-9"))?.codec {
                Codec::ZstdDictionary(hash) => Some(hash),
                _ => None,
            };
            chain.push((current, body, length));
            let Some(next) = next else {
                break;
            };
            current = TERRANE_V1
                .from_digest(IdentityKind::Chunk, &next)
                .map_err(|_| invalid("CDC-9"))?;
            body = self
                .verified_body(catalog, &current)
                .await
                .map_err(dictionary_admission_failure)?;
        }
        let mut dictionary = None;
        for (identity, body, length) in chain.into_iter().rev() {
            let decoded = crate::codec::decode_verified(
                &body,
                length,
                &self.inner.config.chunk_profile,
                true,
                &identity,
                dictionary.as_deref(),
            )
            .map_err(|_| invalid("CDC-9"))?;
            dictionary = Some(decoded.plaintext().to_vec());
        }
        dictionary.ok_or_else(|| invalid("CDC-9"))
    }

    async fn validate_chunk_requirements(
        &self,
        catalog: &Catalog,
        requirements: &[ChunkRequirement],
    ) -> Result<(), StoreFailure> {
        let profile = &self.inner.config.chunk_profile;

        // A chunk admitted as final has not proved a non-final CDC boundary.
        // Recheck each reference's independent context before metadata dedup.
        for requirement in requirements {
            let identity = &requirement.identity;
            if identity.kind() != IdentityKind::Chunk || identity.profile() != TERRANE_V1.name() {
                return Err(files::malformed());
            }
            let encoded = self
                .verified_body(catalog, identity)
                .await
                .map_err(|error| {
                    if matches!(error.kind(), StoreErrorKind::Absent(_)) {
                        invalid(requirement.missing_rule_id)
                    } else {
                        error
                    }
                })?;
            let envelope = parse_envelope(&encoded).map_err(|_| invalid("CDC-7"))?;
            let dictionary = match envelope.codec {
                Codec::ZstdDictionary(hash) => {
                    Some(self.dictionary_plaintext(catalog, &hash).await?)
                }
                _ => None,
            };
            crate::codec::decode_object_chunk_verified(
                &encoded,
                requirement.declared_plaintext_len,
                profile,
                requirement.position == ChunkPosition::Final,
                identity,
                dictionary.as_deref(),
            )
            .map_err(|error| {
                if requirement.position == ChunkPosition::Final
                    && matches!(error, crate::codec::FrameError::BoundaryMismatch)
                {
                    invalid("CDC-19")
                } else {
                    invalid_chunk(error)
                }
            })?;
        }

        Ok(())
    }
}

impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    FileBucket<F, C, V>
{
    /// Runs the ordinary put path while its caller retains stable exclusion.
    ///
    /// # Errors
    /// Returns the same validation, conflict, corruption, or binding failures as the ordinary operation.
    pub(super) async fn put_locked<const WRITABLE: bool>(
        &self,
        held: &super::held::HeldBucket<'_, F, C, V, WRITABLE>,
        upload: ContentUpload<'_>,
    ) -> Result<Identity, StoreFailure> {
        self.put_locked_contextual(held, upload, None).await
    }

    /// Retains an actual native publication context on ordinary fallback puts.
    ///
    /// # Errors
    /// Preserves ordinary admission failures and rejects expired or changed
    /// native current/control inputs before effects and acknowledgment.
    pub(super) async fn put_locked_contextual<const WRITABLE: bool>(
        &self,
        held: &super::held::HeldBucket<'_, F, C, V, WRITABLE>,
        upload: ContentUpload<'_>,
        context: Option<
            &crate::selected_bridge::native_guard::meta_batch::ImmutableEffectContext<'_, '_>,
        >,
    ) -> Result<Identity, StoreFailure> {
        if let Some(context) = context {
            held.retained_namespace()?;
            context.recheck()?;
        }
        #[cfg(all(test, feature = "tokio", unix))]
        self.inner.content_observation.put(match upload {
            ContentUpload::Chunk(_) => IdentityKind::Chunk,
            ContentUpload::Meta(meta) => meta.kind(),
        });

        if !std::ptr::eq(self, held.bucket()) {
            return Err(files::layout_corrupt());
        }
        let observed = held.observe_publication().await?;
        if let Some(context) = context {
            context.check_selection(&observed)?;
        }
        self.write_layout_locked().await?;
        let catalog = self.catalog_observed(&observed).await?;
        let mut dictionaries = BTreeMap::new();
        let identity = match upload {
            ContentUpload::Chunk(chunk) => {
                if chunk.profile != &self.inner.config.chunk_profile {
                    return Err(invalid("CDC-3"));
                }
                let envelope = parse_envelope(chunk.encoded).map_err(|_| invalid("CDC-7"))?;
                if let Codec::ZstdDictionary(hash) = envelope.codec {
                    dictionaries.insert(hash, self.dictionary_plaintext(&catalog, &hash).await?);
                }
                let dictionary = match envelope.codec {
                    Codec::ZstdDictionary(hash) => dictionaries.get(&hash).map(Vec::as_slice),
                    _ => None,
                };
                crate::codec::decode_verified(
                    chunk.encoded,
                    chunk.declared_plaintext_len,
                    chunk.profile,
                    chunk.position == ChunkPosition::Final,
                    chunk.identity,
                    dictionary,
                )
                .map_err(invalid_chunk)?;
                chunk.identity.clone()
            }
            ContentUpload::Meta(meta) => {
                self.inner.validator.validate_meta(&meta)?;
                let requirements = self.inner.validator.chunk_requirements(&meta)?;
                self.validate_chunk_requirements(&catalog, &requirements)
                    .await?;
                TERRANE_V1
                    .calculate(meta.kind(), meta.bytes())
                    .map_err(|_| invalid("STORE-33"))?
            }
        };

        if identity.kind() == IdentityKind::Index && !self.index_retirement_known(&catalog) {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        // A detached index names its physical pack incarnation. Reoffering
        // those container bytes as metadata cannot bypass physical retirement.
        if identity.kind() == IdentityKind::Index
            && catalog.inventory.as_ref().is_some_and(|entries| {
                entries.iter().any(|entry| {
                    entry.index_hash == identity.digest()
                        && self.physically_excluded(&catalog, &entry.pack_id)
                })
            })
        {
            return Err(StoreFailure::new(StoreErrorKind::Absent(identity)));
        }
        if let ContentUpload::Meta(meta) = upload
            && meta.kind() == IdentityKind::Index
            && self
                .detached_index_excluded(&catalog, meta.bytes())
                .map_err(|_| invalid("STORE-33"))?
        {
            return Err(StoreFailure::new(StoreErrorKind::Absent(identity)));
        }
        if let ContentUpload::Meta(meta) = upload
            && meta.kind() == IdentityKind::Pack
        {
            if context.is_some() {
                return Err(StoreFailure::new(StoreErrorKind::Unsupported));
            }
            observed.revalidate().await?;
            return self
                .import_pack(held, &observed, catalog, meta.bytes(), identity)
                .await;
        }
        if self.is_quarantined(&catalog, &identity)? {
            return Err(corrupt(&identity));
        }
        if !self.is_excluded(&catalog, &identity)?
            && self.container(&catalog, &identity).await?.is_some()
        {
            observed.revalidate().await?;
            if let Some(context) = context {
                context.recheck()?;
            }
            return Ok(identity);
        }

        // Admission context is checked even on a dedup hit. Final admission
        // never supplies evidence for a later nonfinal offer of the same bytes.
        if identity == empty_chunk()? {
            observed.revalidate().await?;
            if let Some(context) = context {
                context.recheck()?;
            }
            return Ok(identity);
        }
        let placement = self
            .placement_observed(held, &observed, &catalog, &identity)
            .await?;
        if placement
            .as_ref()
            .is_none_or(|placement| !placement.is_missing())
            && self.location(&catalog, &identity).is_ok()
        {
            let existing = self.verified_body(&catalog, &identity).await?;
            if let ContentUpload::Meta(meta) = upload
                && existing != meta.bytes()
            {
                return Err(corrupt(&identity));
            }
            // Chunk encodings may differ after complete plaintext identity
            // verification; preserve the first verified selected encoding.
            observed.revalidate().await?;
            if let Some(placement) = &placement {
                self.recheck_placement(placement).await?;
            }
            if let Some(context) = context {
                context.recheck()?;
            }
            return Ok(identity);
        }
        let id = PackId::generate(&self.inner.fs)
            .await
            .map_err(files::io_failure)?;
        if catalog
            .inventory
            .as_ref()
            .is_some_and(|entries| entries.iter().any(|entry| entry.pack_id == *id.as_bytes()))
        {
            // Secure entropy does not permit reuse of an already selected
            // physical incarnation, even when its old artifacts are missing.
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        let writer = match upload {
            ContentUpload::Chunk(chunk) => {
                let mut writer = PackWriter::new(id, PackClass::Data, false);
                let hash = identity
                    .terrane_v1_digest()
                    .map_err(|_| invalid("CDC-14"))?;
                let length =
                    u32::try_from(chunk.declared_plaintext_len).map_err(|_| invalid("CDC-12"))?;
                let decoder = NativeBodyDecoder::new(chunk.profile, &dictionaries);
                writer
                    .append_chunk(hash, chunk.encoded, length, 0, &decoder)
                    .map_err(|_| invalid("STORE-33"))?;
                writer
            }
            ContentUpload::Meta(meta) => {
                let mut writer = PackWriter::new(id, PackClass::Meta, false);
                writer
                    .append_raw(entry_kind(meta.kind())?, meta.bytes())
                    .map_err(|_| invalid("STORE-33"))?;
                writer
            }
        };
        let sealed = writer.seal().map_err(|_| invalid("STORE-33"))?;
        let artifacts =
            super::containers::admitted_artifacts(id, sealed.bytes(), sealed.index_object())?;
        match context {
            Some(context) => {
                crate::store::native_publication_effects::stage_container_contextual(
                    held.fs(),
                    &observed,
                    &artifacts,
                    context,
                )
                .await?
            }
            None => {
                crate::store::native_publication_effects::stage_container(
                    held.fs(),
                    &observed,
                    &artifacts,
                )
                .await?
            }
        }
        let generation = catalog
            .capabilities
            .generation
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(files::layout_corrupt)?;
        let index = PackIndexSnapshot::decode(sealed.index_object(), generation)
            .map_err(|_| files::layout_corrupt())?;
        self.verified_container(artifacts.inventory()).await?;
        match context {
            Some(context) => {
                self.publish_pack_catalog_contextual(
                    held,
                    &observed,
                    super::catalog::CatalogAdmission {
                        catalog,
                        new: index,
                        inventory: artifacts.inventory().clone(),
                    },
                    super::catalog::CatalogScope {
                        placement: placement.as_ref(),
                        context: Some(context),
                    },
                )
                .await?
            }
            None => match placement.as_ref() {
                Some(placement) => {
                    self.publish_pack_catalog_observed(
                        held,
                        &observed,
                        catalog,
                        index,
                        artifacts.inventory().clone(),
                        Some(placement),
                    )
                    .await?
                }
                None => {
                    self.publish_pack_catalog(
                        held,
                        &observed,
                        catalog,
                        index,
                        artifacts.inventory().clone(),
                    )
                    .await?
                }
            },
        }
        if let Some(context) = context {
            context.recheck()?;
        }
        Ok(identity)
    }

    /// Runs the ordinary get path while its caller retains stable exclusion.
    ///
    /// # Errors
    /// Returns the same validation, conflict, corruption, or binding failures as the ordinary operation.
    pub(super) async fn get_locked(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        #[cfg(all(test, feature = "tokio", unix))]
        self.inner.content_observation.get(identity.kind());

        let catalog = self.catalog().await?;
        self.get_catalog_body(&catalog, identity, range).await
    }

    /// Verifies a body against one fresh held catalog and revalidates before return.
    ///
    /// No selected observation survives this individual read. Direct artifacts,
    /// body/dictionary verification and range validation retain their original
    /// order, followed by a complete physical and selected-state recheck.
    ///
    /// # Errors
    /// Preserves content, range and unavailable-read failures and rejects changed
    /// selected state, leaf incarnations or ancestry before successful disclosure.
    pub(super) async fn get_held<const WRITABLE: bool>(
        &self,
        held: &super::held::HeldBucket<'_, F, C, V, WRITABLE>,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        #[cfg(all(test, feature = "tokio", unix))]
        self.inner.content_observation.get(identity.kind());

        if !std::ptr::eq(self, held.bucket()) {
            return Err(files::layout_corrupt());
        }
        let observed = held.observe_for_read().await?;
        let catalog = self.catalog_observed(&observed).await?;
        let bytes = self.get_catalog_body(&catalog, identity, range).await?;
        observed.revalidate().await?;
        Ok(bytes)
    }

    async fn get_catalog_body(
        &self,
        catalog: &Catalog,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        let bytes = self.verified_body(catalog, identity).await?;
        let Some(range) = range else {
            return Ok(bytes);
        };
        let end = range.start.checked_add(range.length).ok_or_else(|| {
            StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::Range(range)))
        })?;
        if end > bytes.len() as u64 {
            return Err(StoreFailure::new(StoreErrorKind::Invalid(
                InvalidReason::Range(range),
            )));
        }
        let start = usize::try_from(range.start).map_err(|_| files::malformed())?;
        let end = usize::try_from(end).map_err(|_| files::malformed())?;
        Ok(bytes[start..end].to_vec())
    }

    /// Runs the ordinary has path while its caller retains stable exclusion.
    ///
    /// # Errors
    /// Returns the same validation, conflict, corruption, or binding failures as the ordinary operation.
    pub(super) async fn has_locked(
        &self,
        identities: &[Identity],
    ) -> Result<Vec<bool>, StoreFailure> {
        let catalog = self.catalog().await?;
        let mut results = Vec::with_capacity(identities.len());
        for identity in identities {
            match self.verified_body(&catalog, identity).await {
                Ok(_) => results.push(true),
                Err(error) if matches!(error.kind(), StoreErrorKind::Absent(_)) => {
                    results.push(false)
                }
                Err(error) => return Err(error),
            }
        }
        Ok(results)
    }

    /// Runs the ordinary list path while its caller retains stable exclusion.
    ///
    /// # Errors
    /// Returns the same validation, conflict, corruption, or binding failures as the ordinary operation.
    pub(super) async fn list_locked(
        &self,
        prefix: &IdentityPrefix,
    ) -> Result<Vec<Identity>, StoreFailure> {
        let identities = self.live_identities_locked(prefix.kind).await?;
        Ok(identities
            .into_iter()
            .filter(|identity| identity.digest().starts_with(&prefix.digest_prefix))
            .collect())
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature="send"),async_trait::async_trait(?Send))]
impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    ContentStore for FileBucket<F, C, V>
{
    async fn put(&self, upload: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        let holder = super::held::SingleHeld::acquire(self).await?;
        holder.destination().put(upload).await
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        #[cfg(test)]
        let mut trace = crate::ref_advance::PhaseTrace::new(
            &self.inner.clock,
            "content-get",
            identity.terrane_v1_digest().ok(),
            None,
            "content-get-exclusion-submitted",
        );
        let _guard = self.read_exclusion().await?;
        #[cfg(test)]
        trace.mark("content-get-exclusion-acquired");
        let value = self.get_locked(identity, range).await?;
        #[cfg(test)]
        trace.mark("content-get-value-returned");
        self.ensure_layout().await?;
        #[cfg(test)]
        trace.mark("content-get-closing-layout-checked");
        Ok(value)
    }

    async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        let _guard = self.read_exclusion().await?;
        let value = self.has_locked(identities).await?;
        self.ensure_layout().await?;
        Ok(value)
    }

    async fn list(&self, prefix: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        let _guard = self.read_exclusion().await?;
        let value = self.list_locked(prefix).await?;
        self.ensure_layout().await?;
        Ok(value)
    }
}
