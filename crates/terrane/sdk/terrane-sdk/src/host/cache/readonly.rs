//! Reads existing encoded host content without initializing a bucket authority.
//!
//! Every result is freshly verified. Sealed plaintext is deliberately excluded:
//! manifest identities continue to address canonical manifest bytes.

use super::{DomainHostLayout, HostReadLocation};
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
use terrane_format::{
    identity::{Identity, IdentityKind, TERRANE_V1},
    properties::Domain,
};

/// Bounds each host-reader allocation as operator resource policy.
///
/// This is not an encoded-format maximum. A valid larger object returns
/// capacity and may be fetched through another tier or a larger configured budget.
#[derive(Clone, Copy, Debug)]
pub struct HostReadLimits {
    /// Maximum bytes in any single encoded metadata, pack, index or range read.
    pub max_allocation_bytes: usize,
}

pub(super) struct EncodedRead {
    pub(super) bytes: Vec<u8>,
    pub(super) pack: Option<(PackId, ByteRange)>,
}

impl Default for HostReadLimits {
    fn default() -> Self {
        Self {
            max_allocation_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Provides domain-bound verified encoded reads over an existing host cache.
///
/// Opening and reading never create, repair, probe, or publish filesystem data.
/// Authorization remains with the caller's trusted domain routing boundary.
pub struct HostReadOnlyContent<F, V, L = DomainHostLayout> {
    layout: L,
    fs: F,
    validator: V,
    capabilities: Capabilities,
    directory_identity: (u64, u64),
    limits: HostReadLimits,
}

impl<F: LocalFs + BucketBinding, V: ContentValidator + BucketBinding> HostReadOnlyContent<F, V> {
    /// Opens an existing layout with a 64 MiB per-allocation read budget.
    ///
    /// The budget is operator resource policy, not a format maximum. Larger
    /// metadata can use `open_existing_with_limits`; excess returns capacity.
    ///
    /// # Errors
    /// Refuses private-domain shared caches, missing roots, symlinks, and I/O failures.
    pub async fn open_existing(
        layout: DomainHostLayout,
        fs: F,
        validator: V,
    ) -> Result<Self, StoreFailure> {
        Self::open_existing_with_limits(layout, fs, validator, HostReadLimits::default()).await
    }

    /// Opens an existing layout with an explicit operator allocation budget.
    ///
    /// # Errors
    /// Returns the same layout errors as `open_existing`, or capacity for zero
    /// budget. Reads exceeding this budget return capacity without format rejection.
    pub async fn open_existing_with_limits(
        layout: DomainHostLayout,
        fs: F,
        validator: V,
        limits: HostReadLimits,
    ) -> Result<Self, StoreFailure> {
        if limits.max_allocation_bytes == 0 {
            return Err(resource());
        }
        if matches!(
            Domain::parse(&layout.domain_binding().domain),
            Ok(Domain::Private(_))
        ) {
            return Err(StoreFailure::new(StoreErrorKind::Denied {
                verb: "read",
                pattern: layout.domain_binding().domain.clone(),
            }));
        }
        Self::open_location(layout, fs, validator, limits).await
    }
}

impl<F: LocalFs + BucketBinding, V: ContentValidator + BucketBinding, L: HostReadLocation>
    HostReadOnlyContent<F, V, L>
{
    // Guest routing policy belongs to the repository-bound constructors above.
    // Only the metadata-only sibling view can open host-local private locations;
    // it never exposes this inner ContentStore to its caller.
    pub(super) async fn open_location(
        layout: L,
        fs: F,
        validator: V,
        limits: HostReadLimits,
    ) -> Result<Self, StoreFailure> {
        if limits.max_allocation_bytes == 0 {
            return Err(resource());
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
            limits,
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
    pub fn layout(&self) -> &L {
        &self.layout
    }

    /// Returns the configured per-allocation encoded read budget.
    pub fn read_limits(&self) -> HostReadLimits {
        self.limits
    }

    /// Returns the root device and inode observed during read-only opening.
    ///
    /// This observation detects configured aliases; it grants no authority.
    pub fn directory_identity(&self) -> (u64, u64) {
        self.directory_identity
    }

    async fn directory_chain(
        &self,
        directory: &Path,
    ) -> Result<Option<Vec<(PathBuf, std::fs::Metadata)>>, StoreFailure> {
        let relative = directory
            .strip_prefix(self.layout.root())
            .map_err(|_| invalid())?;
        let mut current = self.layout.root().to_owned();
        let root = self
            .fs
            .symlink_metadata(&current)
            .await
            .map_err(io_failure)?;
        if directory_identity(&root) != Some(self.directory_identity)
            || !root.is_dir()
            || root.file_type().is_symlink()
        {
            return Err(invalid());
        }
        let mut observations = vec![(current.clone(), root)];
        for component in relative.components() {
            current.push(component.as_os_str());
            let metadata = match self.fs.symlink_metadata(&current).await {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    self.close_parents(observations).await?;
                    return Ok(None);
                }
                Err(error) => return Err(io_failure(error)),
            };
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(invalid());
            }
            observations.push((current.clone(), metadata));
        }
        Ok(Some(observations))
    }

    async fn observe_parents(
        &self,
        path: &Path,
    ) -> Result<Vec<(PathBuf, std::fs::Metadata)>, StoreFailure> {
        let parent = path.parent().ok_or_else(invalid)?;
        self.directory_chain(parent).await?.ok_or_else(invalid)
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
        self.read_file_checked(path, None).await
    }

    async fn read_file_checked(
        &self,
        path: &Path,
        chunk: Option<(&Identity, usize)>,
    ) -> Result<Vec<u8>, StoreFailure> {
        let parents = self.observe_parents(path).await?;
        let before = self.fs.symlink_metadata(path).await.map_err(io_failure)?;
        if !before.is_file() || before.file_type().is_symlink() {
            return Err(invalid());
        }
        if let Some((identity, bound)) = chunk
            && before.len() > bound as u64
        {
            return Err(corrupt(
                identity,
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "chunk exceeds existing encoded-size bound",
                ),
            ));
        }
        let bytes = self
            .read_range_checked(
                path,
                ByteRange {
                    start: 0,
                    length: before.len(),
                },
            )
            .await?;
        let after = self.fs.symlink_metadata(path).await.map_err(io_failure)?;
        if !same_file(&before, &after) {
            return Err(invalid());
        }
        self.close_parents(parents).await?;
        Ok(bytes)
    }

    async fn read_range_checked(
        &self,
        path: &Path,
        range: ByteRange,
    ) -> Result<Vec<u8>, StoreFailure> {
        if range.length > self.limits.max_allocation_bytes as u64 {
            return Err(resource());
        }
        range.start.checked_add(range.length).ok_or_else(resource)?;
        let bytes = self.fs.read_range(path, range).await.map_err(io_failure)?;
        if bytes.len() as u64 != range.length {
            return Err(invalid());
        }
        Ok(bytes)
    }

    fn check_index_allocation(&self, bytes: &[u8]) -> Result<(), StoreFailure> {
        use terrane_format::pack_format::{HEADER_SIZE, RECORD_SIZE, Record, index_count};
        let index = bytes.get(HEADER_SIZE..).ok_or_else(invalid)?;
        let count = index_count(index, RECORD_SIZE).map_err(|_| invalid())?;
        if count
            .checked_mul(std::mem::size_of::<Record>())
            .ok_or_else(resource)?
            > self.limits.max_allocation_bytes
        {
            return Err(resource());
        }
        Ok(())
    }

    async fn directory_entries(&self, directory: &Path) -> Result<Vec<PathBuf>, StoreFailure> {
        let Some(parents) = self.directory_chain(directory).await? else {
            return Ok(Vec::new());
        };
        let entries = self.fs.read_dir(directory).await.map_err(io_failure)?;
        self.close_parents(parents).await?;
        for path in &entries {
            if path.parent() != Some(directory) {
                return Err(invalid());
            }
        }
        Ok(entries)
    }

    async fn pack_paths(&self) -> Result<Vec<PathBuf>, StoreFailure> {
        let mut paths = Vec::new();
        for directory in self
            .directory_entries(&self.layout.root().join("objects/pack"))
            .await?
        {
            for path in self.directory_entries(&directory).await? {
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

    async fn standalone_identities(
        &self,
        max_entries: usize,
    ) -> Result<Vec<Identity>, StoreFailure> {
        let mut identities = BTreeMap::new();
        for directory in self
            .directory_entries(&self.layout.root().join("chunks"))
            .await?
        {
            let shard = directory
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(invalid)?;
            for path in self.directory_entries(&directory).await? {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(invalid)?;
                if name.starts_with('.') || name.ends_with(".tmp") {
                    continue;
                }
                let (hash, codec) = name.rsplit_once('.').ok_or_else(invalid)?;
                if !matches!(codec, "0" | "1" | "2")
                    || hash.len() != 64
                    || shard.len() != 2
                    || !hash.starts_with(shard)
                    || !hash
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(invalid());
                }
                let mut digest = [0_u8; 32];
                for (index, byte) in digest.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&hash[index * 2..index * 2 + 2], 16)
                        .map_err(|_| invalid())?;
                }
                let identity = TERRANE_V1
                    .from_digest(IdentityKind::Chunk, &digest)
                    .map_err(|_| invalid())?;
                if !identities.contains_key(&digest) && identities.len() >= max_entries {
                    return Err(resource());
                }
                identities.insert(digest, identity);
            }
        }
        Ok(identities.into_values().collect())
    }

    async fn encoded(&self, identity: &Identity) -> Result<Vec<u8>, StoreFailure> {
        self.encoded_with_dictionary(identity, true).await
    }

    async fn encoded_with_dictionary(
        &self,
        identity: &Identity,
        allow_dictionary: bool,
    ) -> Result<Vec<u8>, StoreFailure> {
        Ok(self.read_encoded(identity, allow_dictionary).await?.bytes)
    }

    pub(super) async fn read_encoded(
        &self,
        identity: &Identity,
        allow_dictionary: bool,
    ) -> Result<EncodedRead, StoreFailure> {
        if identity.profile() != TERRANE_V1.name() || identity.digest().len() != 32 {
            return Err(invalid());
        }
        if identity.kind() == IdentityKind::Chunk {
            match self.standalone(identity, allow_dictionary).await {
                Ok(bytes) => return Ok(EncodedRead { bytes, pack: None }),
                Err(error) if matches!(error.kind(), StoreErrorKind::Absent(_)) => {}
                Err(error) => return Err(error),
            }
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
                    return Ok(EncodedRead { bytes, pack: None });
                }
                continue;
            }
            let index_path = path.with_extension("idx");
            let index_bytes = self.read_file(&index_path).await?;
            self.check_index_allocation(&index_bytes)?;
            let (header, records) =
                terrane_format::pack_format::decode_detached_index(&index_bytes)
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
            if identity.kind() == IdentityKind::Chunk
                && (record.plaintext_len as usize > self.layout.chunk_profile().maximum()
                    || record.body_len as usize
                        > super::maximum_encoded_chunk_bytes(self.layout.chunk_profile())
                            .map_err(|error| corrupt(identity, error))?)
            {
                return Err(corrupt(
                    identity,
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "pack chunk declaration exceeds existing codec bounds",
                    ),
                ));
            }
            let parents = self.observe_parents(&path).await?;
            let before = self.fs.symlink_metadata(&path).await.map_err(io_failure)?;
            if !before.is_file() || before.file_type().is_symlink() {
                return Err(invalid());
            }
            self.verify_pack_index(&path, before.len(), &index_bytes, &records)
                .await
                .map_err(|source| {
                    if matches!(source.kind(), StoreErrorKind::Capacity) {
                        source
                    } else {
                        corrupt(identity, source)
                    }
                })?;
            let bytes = self
                .read_range_checked(
                    &path,
                    ByteRange {
                        start: record.offset,
                        length: u64::from(record.body_len),
                    },
                )
                .await?;
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
            return Ok(EncodedRead {
                bytes,
                pack: Some((
                    PackId::from_random_bytes(*header.id()),
                    ByteRange {
                        start: record.offset,
                        length: u64::from(record.body_len),
                    },
                )),
            });
        }
        Err(StoreFailure::new(StoreErrorKind::Absent(identity.clone())))
    }

    async fn standalone(
        &self,
        identity: &Identity,
        allow_dictionary: bool,
    ) -> Result<Vec<u8>, StoreFailure> {
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
                let Some(parents) = self
                    .directory_chain(path.parent().ok_or_else(invalid)?)
                    .await?
                else {
                    continue;
                };
                match self.fs.symlink_metadata(&path).await {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        self.close_parents(parents).await?;
                        continue;
                    }
                    Err(error) => return Err(io_failure(error)),
                    Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
                        return Err(invalid());
                    }
                    Ok(metadata) => {
                        if metadata.len()
                            > super::maximum_encoded_chunk_bytes(self.layout.chunk_profile())
                                .map_err(|error| corrupt(identity, error))?
                                as u64
                        {
                            return Err(corrupt(
                                identity,
                                std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "standalone body exceeds existing codec bounds",
                                ),
                            ));
                        }
                    }
                }
                self.close_parents(parents).await?;
                let bound = super::maximum_encoded_chunk_bytes(self.layout.chunk_profile())
                    .map_err(|error| corrupt(identity, error))?;
                let bytes = self
                    .read_file_checked(&path, Some((identity, bound)))
                    .await?;
                if bytes.first() != Some(&codec) {
                    return Err(corrupt(
                        identity,
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "chunk filename codec differs from body",
                        ),
                    ));
                }
                let envelope = terrane_format::codec::parse_envelope(&bytes)
                    .map_err(|error| corrupt(identity, error))?;
                let length = match envelope.codec {
                    terrane_format::codec::Codec::Raw => envelope.body.len(),
                    terrane_format::codec::Codec::Zstd
                    | terrane_format::codec::Codec::ZstdDictionary(_) => {
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
        records: &[terrane_format::pack_format::Record],
    ) -> Result<(), StoreFailure> {
        use terrane_format::pack_format::{FOOTER_SIZE, HEADER_SIZE, crc32c};
        let footer_start = file_size
            .checked_sub(FOOTER_SIZE as u64)
            .ok_or_else(invalid)?;
        let header = self
            .read_range_checked(
                path,
                ByteRange {
                    start: 0,
                    length: HEADER_SIZE as u64,
                },
            )
            .await?;
        if detached.get(..HEADER_SIZE) != Some(header.as_slice()) {
            return Err(invalid());
        }
        let footer = self
            .read_range_checked(
                path,
                ByteRange {
                    start: footer_start,
                    length: FOOTER_SIZE as u64,
                },
            )
            .await?;
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
            .read_range_checked(
                path,
                ByteRange {
                    start: offset,
                    length: expected.len() as u64,
                },
            )
            .await?;
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
        let envelope = terrane_format::codec::parse_envelope(encoded)
            .map_err(|error| corrupt(identity, error))?;
        let dictionary = if let terrane_format::codec::Codec::ZstdDictionary(digest) =
            envelope.codec
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
            let dictionary_envelope = terrane_format::codec::parse_envelope(&bytes)
                .map_err(|error| corrupt(&dictionary_identity, error))?;
            let dictionary_length = match dictionary_envelope.codec {
                terrane_format::codec::Codec::Raw => dictionary_envelope.body.len(),
                terrane_format::codec::Codec::Zstd => {
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

    pub(super) async fn list_bounded(
        &self,
        prefix: &IdentityPrefix,
        max_entries: usize,
    ) -> Result<Vec<Identity>, StoreFailure> {
        let mut identities = BTreeMap::new();
        for path in self.pack_paths().await? {
            let bytes = self.read_file(&path).await?;
            let reader = PackReader::open(&bytes).map_err(|error| {
                StoreFailure::with_source(
                    StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
                    error,
                )
            })?;
            if self.layout.root().join(reader.header().id().pack_key()) != path {
                return Err(invalid());
            }
            if prefix.kind == IdentityKind::Pack {
                let identity = TERRANE_V1
                    .calculate(IdentityKind::Pack, &bytes)
                    .map_err(|_| invalid())?;
                if identity.digest().starts_with(&prefix.digest_prefix) {
                    insert_list_identity(&mut identities, identity, max_entries)?;
                }
            }
            for entry in reader.entries() {
                if entry.kind().identity_kind() == prefix.kind
                    && entry.hash().starts_with(&prefix.digest_prefix)
                {
                    let identity = TERRANE_V1
                        .from_digest(prefix.kind, entry.hash())
                        .map_err(|_| invalid())?;
                    insert_list_identity(&mut identities, identity, max_entries)?;
                }
            }
        }
        if prefix.kind == IdentityKind::Chunk {
            for identity in self.standalone_identities(max_entries).await? {
                if identity.digest().starts_with(&prefix.digest_prefix) {
                    insert_list_identity(&mut identities, identity, max_entries)?;
                }
            }
        }
        let mut verified = Vec::with_capacity(identities.len());
        for identity in identities.into_values() {
            self.encoded(&identity).await?;
            verified.push(identity);
        }
        Ok(verified)
    }
}

impl<F, V, L> CapabilityReport for HostReadOnlyContent<F, V, L> {
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<F: LocalFs + BucketBinding, V: ContentValidator + BucketBinding, L: HostReadLocation>
    ContentStore for HostReadOnlyContent<F, V, L>
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
        self.list_bounded(prefix, usize::MAX).await
    }
}

fn insert_list_identity(
    identities: &mut BTreeMap<Vec<u8>, Identity>,
    identity: Identity,
    max_entries: usize,
) -> Result<(), StoreFailure> {
    if !identities.contains_key(identity.digest()) && identities.len() >= max_entries {
        return Err(resource());
    }
    identities.insert(identity.digest().to_vec(), identity);
    Ok(())
}

fn resource() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Capacity)
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
pub(super) fn same_file(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
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
pub(super) fn same_file(_before: &std::fs::Metadata, _after: &std::fs::Metadata) -> bool {
    false
}

fn range_failure(range: ByteRange) -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::Range(range)))
}
