//! Reads existing encoded host content without initializing a bucket authority.
//!
//! Every result is freshly verified. Sealed plaintext is deliberately excluded:
//! manifest identities continue to address canonical manifest bytes.

use super::DomainHostLayout;
#[cfg(all(feature = "tokio", unix))]
use crate::store::{NativeOrdinaryRead, OrdinaryReadOutcome};
use crate::{
    bucket::BucketBinding,
    pack::{PackId, PackReader},
    store::{
        ByteRange, Capabilities, CapabilityReport, ContentStore, ContentUpload, ContentValidator,
        CorruptSubject, Durability, IdentityPrefix, InvalidReason, LocalFs, MetaUpload,
        RangeCapability, RefCapability, StoreErrorKind, StoreFailure,
    },
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use terrane_core::{
    identity::{Identity, IdentityKind, TERRANE_V1},
    properties::Domain,
};

/// Provides domain-bound verified encoded reads over an existing host cache.
///
/// Opening and reading never create, repair, probe, or publish filesystem data.
/// Authorization remains with the caller's trusted domain routing boundary.
pub struct HostReadOnlyContent<F, V> {
    layout: DomainHostLayout,
    fs: F,
    validator: V,
    capabilities: Capabilities,
    directory_identity: (u64, u64),
}

impl<F: LocalFs + BucketBinding, V: ContentValidator + BucketBinding> HostReadOnlyContent<F, V> {
    /// Opens an existing domain layout without writable bucket probes.
    ///
    /// # Errors
    /// Refuses private-domain shared caches, missing roots, symlinks, and I/O failures.
    pub async fn open_existing(
        layout: DomainHostLayout,
        fs: F,
        validator: V,
    ) -> Result<Self, StoreFailure> {
        if matches!(
            Domain::parse(&layout.domain_binding().domain),
            Ok(Domain::Private(_))
        ) {
            return Err(StoreFailure::new(StoreErrorKind::Denied {
                verb: "read",
                pattern: layout.domain_binding().domain.clone(),
            }));
        }
        let mut ancestor = PathBuf::from("/");
        for component in layout.root().components() {
            ancestor.push(component.as_os_str());
            let metadata = fs.symlink_metadata(&ancestor).await.map_err(io_failure)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(invalid());
            }
        }
        let metadata = fs
            .symlink_metadata(layout.root())
            .await
            .map_err(io_failure)?;
        let directory_identity = directory_identity(&metadata)
            .ok_or_else(|| StoreFailure::new(StoreErrorKind::Unsupported))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(invalid());
        }
        let reader = Self {
            layout,
            fs,
            validator,
            directory_identity,
            capabilities: Capabilities {
                refs: RefCapability::None,
                ranges: RangeCapability::Ranges,
                presign: false,
                locality: Default::default(),
                durability: Durability::Local,
                sealed: false,
            },
        };
        Ok(reader)
    }

    /// Returns the immutable domain routing configuration.
    pub fn layout(&self) -> &DomainHostLayout {
        &self.layout
    }

    /// Returns the root device and inode observed during read-only opening.
    ///
    /// This observation detects configured aliases; it grants no authority.
    pub fn directory_identity(&self) -> (u64, u64) {
        self.directory_identity
    }

    async fn observe_parents(
        &self,
        path: &Path,
    ) -> Result<Vec<(PathBuf, std::fs::Metadata)>, StoreFailure> {
        let relative = path
            .strip_prefix(self.layout.root())
            .map_err(|_| invalid())?;
        let mut parent = self.layout.root().to_owned();
        let root = self
            .fs
            .symlink_metadata(&parent)
            .await
            .map_err(io_failure)?;
        if directory_identity(&root) != Some(self.directory_identity)
            || !root.is_dir()
            || root.file_type().is_symlink()
        {
            return Err(invalid());
        }
        let mut observations = vec![(parent.clone(), root)];
        let components: Vec<_> = relative.components().collect();
        for component in components.iter().take(components.len().saturating_sub(1)) {
            parent.push(component.as_os_str());
            let metadata = self
                .fs
                .symlink_metadata(&parent)
                .await
                .map_err(io_failure)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(invalid());
            }
            observations.push((parent.clone(), metadata));
        }
        Ok(observations)
    }

    async fn close_parents(
        &self,
        observations: Vec<(PathBuf, std::fs::Metadata)>,
    ) -> Result<(), StoreFailure> {
        for (path, before) in observations {
            let after = self.fs.symlink_metadata(&path).await.map_err(io_failure)?;
            if directory_identity(&before) != directory_identity(&after)
                || !after.is_dir()
                || after.file_type().is_symlink()
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    async fn read_file(&self, path: &Path) -> Result<Vec<u8>, StoreFailure> {
        let parents = self.observe_parents(path).await?;
        let before = self.fs.symlink_metadata(path).await.map_err(io_failure)?;
        if !before.is_file() || before.file_type().is_symlink() {
            return Err(invalid());
        }
        let bytes = self.read_leaf(path).await?;
        let after = self.fs.symlink_metadata(path).await.map_err(io_failure)?;
        if !same_file(&before, &after) {
            return Err(invalid());
        }
        self.close_parents(parents).await?;
        Ok(bytes)
    }

    async fn read_leaf(&self, path: &Path) -> Result<Vec<u8>, StoreFailure> {
        #[cfg(all(feature = "tokio", unix))]
        if let Some(record) = self
            .fs
            .read_ordinary_record(NativeOrdinaryRead::for_leaf(path))
            .await
            .map_err(io_failure)?
        {
            return match record.into_outcome() {
                OrdinaryReadOutcome::Present(bytes, _) => Ok(bytes),
                _ => Err(invalid()),
            };
        }
        self.fs.read_nofollow(path).await.map_err(io_failure)
    }

    async fn pack_paths(&self) -> Result<Vec<PathBuf>, StoreFailure> {
        let root = self.layout.root().join("objects/pack");
        let directories = match self.fs.read_dir(&root).await {
            Ok(paths) => paths,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(io_failure(error)),
        };
        let mut paths = Vec::new();
        for directory in directories {
            let metadata = self
                .fs
                .symlink_metadata(&directory)
                .await
                .map_err(io_failure)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(invalid());
            }
            for path in self.fs.read_dir(&directory).await.map_err(io_failure)? {
                if path
                    .extension()
                    .is_some_and(|extension| extension == "pack")
                {
                    paths.push(path);
                }
            }
        }
        paths.sort();
        Ok(paths)
    }

    async fn encoded(&self, identity: &Identity) -> Result<Vec<u8>, StoreFailure> {
        self.encoded_with_dictionary(identity, true).await
    }

    async fn encoded_with_dictionary(
        &self,
        identity: &Identity,
        allow_dictionary: bool,
    ) -> Result<Vec<u8>, StoreFailure> {
        if identity.profile() != TERRANE_V1.name() || identity.digest().len() != 32 {
            return Err(invalid());
        }
        for path in self.pack_paths().await? {
            if identity.kind() == IdentityKind::Pack {
                let bytes = self.read_file(&path).await?;
                let actual = TERRANE_V1
                    .calculate(IdentityKind::Pack, &bytes)
                    .map_err(|_| invalid())?;
                if &actual == identity {
                    let reader =
                        PackReader::open(&bytes).map_err(|error| corrupt(identity, error))?;
                    if self.layout.root().join(reader.header().id().pack_key()) != path {
                        return Err(invalid());
                    }
                    return Ok(bytes);
                }
                continue;
            }
            let index_path = path.with_extension("idx");
            let index_bytes = self.read_file(&index_path).await?;
            let (header, records) = terrane_core::pack_format::decode_detached_index(&index_bytes)
                .map_err(|error| corrupt(identity, error))?;
            if self
                .layout
                .root()
                .join(PackId::from_random_bytes(*header.id()).pack_key())
                != path
            {
                return Err(invalid());
            }
            let Some(record) = records.iter().find(|record| {
                crate::pack::EntryKind::try_from(record.kind)
                    .is_ok_and(|kind| kind.identity_kind() == identity.kind())
                    && record.hash.as_slice() == identity.digest()
            }) else {
                continue;
            };
            let parents = self.observe_parents(&path).await?;
            let before = self.fs.symlink_metadata(&path).await.map_err(io_failure)?;
            if !before.is_file() || before.file_type().is_symlink() {
                return Err(invalid());
            }
            self.verify_pack_index(&path, before.len(), &index_bytes, &records)
                .await
                .map_err(|source| corrupt(identity, source))?;
            let bytes = self
                .fs
                .read_range(
                    &path,
                    ByteRange {
                        start: record.offset,
                        length: u64::from(record.body_len),
                    },
                )
                .await
                .map_err(io_failure)?;
            let after = self.fs.symlink_metadata(&path).await.map_err(io_failure)?;
            if !same_file(&before, &after) {
                return Err(invalid());
            }
            self.close_parents(parents).await?;
            if bytes.len() != record.body_len as usize
                || (identity.kind() == IdentityKind::Chunk && bytes.first() != Some(&record.codec))
            {
                return Err(corrupt(
                    identity,
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "pack body differs from detached index declarations",
                    ),
                ));
            }
            if identity.kind() == IdentityKind::Chunk {
                self.verify_chunk(
                    &bytes,
                    record.plaintext_len as usize,
                    identity,
                    allow_dictionary,
                )
                .await?;
            } else {
                TERRANE_V1
                    .verify(identity, &bytes)
                    .map_err(|error| corrupt(identity, error))?;
                self.validator
                    .validate_meta(&MetaUpload::new(identity.kind(), &bytes)?)?;
            }
            return Ok(bytes);
        }
        // Standalone bodies retain exactly the same codec envelope as pack bodies.
        let hex: String = identity
            .digest()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        if identity.kind() == IdentityKind::Chunk {
            for codec in 0_u8..=2 {
                let path =
                    self.layout
                        .root()
                        .join(format!("chunks/{}/{}.{}", &hex[..2], hex, codec));
                match self.fs.symlink_metadata(&path).await {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(io_failure(error)),
                    Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
                        return Err(invalid());
                    }
                    Ok(_) => {}
                }
                let bytes = self.read_file(&path).await?;
                if bytes.first() != Some(&codec) {
                    return Err(corrupt(
                        identity,
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "chunk filename codec differs from body",
                        ),
                    ));
                }
                let envelope = terrane_core::codec::parse_envelope(&bytes)
                    .map_err(|error| corrupt(identity, error))?;
                let length = match envelope.codec {
                    terrane_core::codec::Codec::Raw => envelope.body.len(),
                    terrane_core::codec::Codec::Zstd
                    | terrane_core::codec::Codec::ZstdDictionary(_) => {
                        zstd::zstd_safe::get_frame_content_size(envelope.body)
                            .map_err(|_| invalid())?
                            .and_then(|size| usize::try_from(size).ok())
                            .ok_or_else(invalid)?
                    }
                };
                self.verify_chunk(&bytes, length, identity, allow_dictionary)
                    .await?;
                return Ok(bytes);
            }
        }
        Err(StoreFailure::new(StoreErrorKind::Absent(identity.clone())))
    }

    async fn verify_pack_index(
        &self,
        path: &Path,
        file_size: u64,
        detached: &[u8],
        records: &[terrane_core::pack_format::Record],
    ) -> Result<(), StoreFailure> {
        use terrane_core::pack_format::{FOOTER_SIZE, HEADER_SIZE, crc32c};
        let footer_start = file_size
            .checked_sub(FOOTER_SIZE as u64)
            .ok_or_else(invalid)?;
        let header = self
            .fs
            .read_range(
                path,
                ByteRange {
                    start: 0,
                    length: HEADER_SIZE as u64,
                },
            )
            .await
            .map_err(io_failure)?;
        if detached.get(..HEADER_SIZE) != Some(header.as_slice()) {
            return Err(invalid());
        }
        let footer = self
            .fs
            .read_range(
                path,
                ByteRange {
                    start: footer_start,
                    length: FOOTER_SIZE as u64,
                },
            )
            .await
            .map_err(io_failure)?;
        if footer.len() != FOOTER_SIZE || footer.get(12..) != Some(b"TRPE".as_slice()) {
            return Err(invalid());
        }
        let offset = u64::from_le_bytes(
            footer
                .get(..8)
                .ok_or_else(invalid)?
                .try_into()
                .map_err(|_| invalid())?,
        );
        let checksum = u32::from_le_bytes(
            footer
                .get(8..12)
                .ok_or_else(invalid)?
                .try_into()
                .map_err(|_| invalid())?,
        );
        let expected = detached.get(HEADER_SIZE..).ok_or_else(invalid)?;
        if offset < HEADER_SIZE as u64
            || footer_start.checked_sub(offset) != Some(expected.len() as u64)
            || crc32c(expected) != checksum
        {
            return Err(invalid());
        }
        let last_end = records
            .iter()
            .try_fold(HEADER_SIZE as u64, |last, record| {
                let end = record
                    .offset
                    .checked_add(u64::from(record.body_len))
                    .ok_or_else(invalid)?;
                Ok::<_, StoreFailure>(last.max(end))
            })?;
        if last_end != offset {
            return Err(invalid());
        }
        let actual = self
            .fs
            .read_range(
                path,
                ByteRange {
                    start: offset,
                    length: expected.len() as u64,
                },
            )
            .await
            .map_err(io_failure)?;
        if actual != expected {
            return Err(invalid());
        }
        Ok(())
    }

    async fn verify_chunk(
        &self,
        encoded: &[u8],
        length: usize,
        identity: &Identity,
        allow_dictionary: bool,
    ) -> Result<(), StoreFailure> {
        let envelope = terrane_core::codec::parse_envelope(encoded)
            .map_err(|error| corrupt(identity, error))?;
        let dictionary = if let terrane_core::codec::Codec::ZstdDictionary(digest) = envelope.codec
        {
            if !allow_dictionary {
                return Err(StoreFailure::new(StoreErrorKind::Unsupported));
            }
            let dictionary_identity = TERRANE_V1
                .from_digest(IdentityKind::Chunk, &digest)
                .map_err(|_| invalid())?;
            // A dictionary must be independently encoded. This single permitted
            // dependency hop also prevents hostile envelope cycles from recursing.
            let bytes = Box::pin(self.encoded_with_dictionary(&dictionary_identity, false)).await?;
            let dictionary_envelope = terrane_core::codec::parse_envelope(&bytes)
                .map_err(|error| corrupt(&dictionary_identity, error))?;
            let dictionary_length = match dictionary_envelope.codec {
                terrane_core::codec::Codec::Raw => dictionary_envelope.body.len(),
                terrane_core::codec::Codec::Zstd => {
                    zstd::zstd_safe::get_frame_content_size(dictionary_envelope.body)
                        .map_err(|_| invalid())?
                        .and_then(|size| usize::try_from(size).ok())
                        .ok_or_else(invalid)?
                }
                _ => return Err(StoreFailure::new(StoreErrorKind::Unsupported)),
            };
            Some(
                crate::codec::decode_verified(
                    &bytes,
                    dictionary_length,
                    self.layout.chunk_profile(),
                    true,
                    &dictionary_identity,
                    None,
                )
                .map_err(|error| corrupt(&dictionary_identity, error))?
                .plaintext()
                .to_vec(),
            )
        } else {
            None
        };
        crate::codec::decode_verified(
            encoded,
            length,
            self.layout.chunk_profile(),
            true,
            identity,
            dictionary.as_deref(),
        )
        .map_err(|error| corrupt(identity, error))?;
        Ok(())
    }
}

impl<F, V> CapabilityReport for HostReadOnlyContent<F, V> {
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<F: LocalFs + BucketBinding, V: ContentValidator + BucketBinding> ContentStore
    for HostReadOnlyContent<F, V>
{
    async fn put(&self, _upload: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::ReadOnly))
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        if identity.profile() != TERRANE_V1.name() {
            return Err(invalid());
        }
        let bytes = self.encoded(identity).await?;
        match range {
            None => Ok(bytes),
            Some(range) => {
                let start = usize::try_from(range.start).map_err(|_| range_failure(range))?;
                let length = usize::try_from(range.length).map_err(|_| range_failure(range))?;
                let end = start
                    .checked_add(length)
                    .ok_or_else(|| range_failure(range))?;
                bytes
                    .get(start..end)
                    .map(<[u8]>::to_vec)
                    .ok_or_else(|| range_failure(range))
            }
        }
    }

    async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        let mut result = Vec::with_capacity(identities.len());
        for identity in identities {
            match self.encoded(identity).await {
                Ok(_) => result.push(true),
                Err(error) if matches!(error.kind(), StoreErrorKind::Absent(_)) => {
                    result.push(false)
                }
                Err(error) => return Err(error),
            }
        }
        Ok(result)
    }

    async fn list(&self, prefix: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        let mut identities = BTreeMap::new();
        for path in self.pack_paths().await? {
            let bytes = self.read_file(&path).await?;
            let reader = PackReader::open(&bytes).map_err(|error| {
                StoreFailure::with_source(
                    StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
                    error,
                )
            })?;
            for entry in reader.entries() {
                if entry.kind().identity_kind() == prefix.kind
                    && entry.hash().starts_with(&prefix.digest_prefix)
                {
                    let identity = TERRANE_V1
                        .from_digest(prefix.kind, entry.hash())
                        .map_err(|_| invalid())?;
                    identities.insert(entry.hash().to_vec(), identity);
                }
            }
        }
        Ok(identities.into_values().collect())
    }
}

fn invalid() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::MalformedRequest))
}
fn io_failure(error: std::io::Error) -> StoreFailure {
    StoreFailure::with_source(StoreErrorKind::Unavailable { retry_after: None }, error)
}
fn corrupt(
    identity: &Identity,
    source: impl std::error::Error + Send + Sync + 'static,
) -> StoreFailure {
    StoreFailure::with_source(
        StoreErrorKind::Corrupt(CorruptSubject::Identity(identity.clone())),
        source,
    )
}

#[cfg(unix)]
fn directory_identity(metadata: &std::fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn directory_identity(_metadata: &std::fs::Metadata) -> Option<(u64, u64)> {
    None
}

#[cfg(unix)]
fn same_file(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
        && after.is_file()
        && !after.file_type().is_symlink()
}

#[cfg(not(unix))]
fn same_file(_before: &std::fs::Metadata, _after: &std::fs::Metadata) -> bool {
    false
}

fn range_failure(range: ByteRange) -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::Range(range)))
}
