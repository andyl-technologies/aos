//! Descriptor-owned source admission and position-independent streaming bodies.
//!
//! Admission hashes a bounded regular file before remote effects. Every retry
//! owns an independent positional stream and rechecks the exact part digest.
//! Callers retain custody of the file: admission cannot prevent another writer
//! from changing its bytes, so provider checksums and final storage verification
//! remain mandatory.

use std::fmt;
use std::fs::File;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use base64::Engine as _;
use bytes::Bytes;
use futures_util::{Stream, stream};
use md5::Digest as _;
use sha2::Digest as _;

/// Maximum application-owned payload buffer for one source stream.
pub const SOURCE_CHUNK_BYTES: usize = 64 * 1024;

const MAX_SOURCE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// A value-free source admission or read failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceError {
    /// Source size or SHA declaration is unsupported or malformed.
    InvalidDeclaration,
    /// The retained file is not regular or differs from the declared size.
    SizeConflict,
    /// The retained descriptor changed after its hash admission.
    IdentityConflict,
    /// The file or part digest differs from its original declaration.
    DigestConflict,
    /// The requested nonempty range lies outside the declared source.
    InvalidRange,
    /// A descriptor read could not produce all admitted bytes.
    Read,
    /// A blocking source worker could not complete.
    Worker,
    /// Admission was dropped or cooperatively cancelled between source reads.
    Cancelled,
}

impl fmt::Display for SourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidDeclaration => "direct upload source declaration is invalid",
            Self::SizeConflict => "direct upload source size conflicts",
            Self::IdentityConflict => "direct upload source identity changed",
            Self::DigestConflict => "direct upload source digest conflicts",
            Self::InvalidRange => "direct upload source range is invalid",
            Self::Read => "direct upload source read failed",
            Self::Worker => "direct upload source worker failed",
            Self::Cancelled => "direct upload source admission cancelled",
        })
    }
}

impl std::error::Error for SourceError {}

/// Opens a caller-selected regular source without blocking on a Unix FIFO.
///
/// Unix opens use `O_NONBLOCK` before descriptor metadata admission; the flag
/// has no streaming effect on ordinary files. Selected-path symlinks retain
/// their historical semantics. Callers requiring root-relative nofollow custody
/// must continue using their dedicated descriptor opener instead.
///
/// This does not guarantee deadlines for filesystem/kernel I/O. The caller
/// retains source/ancestor custody; admission pins the opened descriptor and
/// later checksum checks refuse changed bytes.
///
/// # Errors
/// Returns a value-free error for open/metadata failure, a nonregular source or
/// a source larger than the supported 16 GiB object limit.
pub fn open_regular_source_file(path: &std::path::Path) -> Result<File, SourceError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
    }
    let file = options.open(path).map_err(|_| SourceError::Read)?;
    let metadata = file.metadata().map_err(|_| SourceError::Read)?;
    if !metadata.is_file() || metadata.len() > MAX_SOURCE_BYTES {
        return Err(SourceError::SizeConflict);
    }
    Ok(file)
}

/// A regular descriptor checked against an exact full-object identity.
#[derive(Clone)]
pub struct AdmittedSource {
    file: Arc<File>,
    stamp: SourceStamp,
    byte_size: u64,
    sha256: String,
    part_size: u64,
    parts: Arc<Vec<HashedPart>>,
}

impl fmt::Debug for AdmittedSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdmittedSource")
            .field("byte_size", &self.byte_size)
            .field("part_size", &self.part_size)
            .field("descriptor", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl AdmittedSource {
    /// Checks retained regular-file bytes against a bounded exact declaration.
    ///
    /// The caller opens and owns the descriptor under its path/custody policy.
    /// This operation does not create, rewrite or initialize a source file.
    /// Dropping the admission future requests cancellation between bounded
    /// reads; it cannot interrupt a blocked filesystem read.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical SHA-256, sizes above the storage-work limit,
    /// nonregular/changed files, short reads, digest conflicts or worker failure.
    pub async fn admit(
        file: File,
        byte_size: u64,
        sha256: &str,
        part_size: u64,
    ) -> Result<Self, SourceError> {
        if byte_size > MAX_SOURCE_BYTES
            || !canonical_sha256(sha256)
            || part_size == 0
            || part_size > 64 * 1024 * 1024
            || byte_size.div_ceil(part_size) > 10_000
        {
            return Err(SourceError::InvalidDeclaration);
        }
        let metadata = file.metadata().map_err(|_| SourceError::Read)?;
        if !metadata.is_file() || metadata.len() != byte_size {
            return Err(SourceError::SizeConflict);
        }

        let stamp = SourceStamp::from_metadata(&metadata);
        let file = Arc::new(file);
        let reader = Arc::clone(&file);
        let cancellation = tokio_util::sync::CancellationToken::new();
        let _cancel_on_drop = cancellation.clone().drop_guard();
        let actual = tokio::task::spawn_blocking(move || {
            hash_source(&reader, byte_size, part_size, &cancellation)
        })
        .await
        .map_err(|_| SourceError::Worker)??;
        if actual.sha256 != sha256 {
            return Err(SourceError::DigestConflict);
        }
        stamp.check(&file, byte_size)?;
        Ok(Self {
            file,
            stamp,
            byte_size,
            sha256: sha256.to_owned(),
            part_size,
            parts: Arc::new(actual.parts),
        })
    }

    /// Returns the exact declared whole-object size.
    pub fn byte_size(&self) -> u64 {
        self.byte_size
    }

    /// Returns the canonical full-object SHA-256 validated at admission.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Returns the immutable part geometry hashed at source admission.
    pub fn part_size(&self) -> u64 {
        self.part_size
    }

    /// Retrieves one exact original part identity before requesting a grant.
    ///
    /// Whole-object and part hashes are collected in the same admission pass.
    /// This operation rehashes the requested part with64 KiB reads against that
    /// original catalogue before a grant can be requested. Metadata alone cannot
    /// detect every write within filesystem timestamp resolution. Later source
    /// changes cannot replace a part's original checksum.
    ///
    /// # Errors
    ///
    /// Rejects geometry that differs from the original admitted part or a
    /// source whose current size differs from the original declaration.
    pub async fn prepare_part(
        &self,
        part_number: u32,
        offset: u64,
        byte_size: u64,
        algorithm: PartChecksumAlgorithm,
    ) -> Result<PartSource, SourceError> {
        if part_number == 0
            || part_number > 10_000
            || byte_size == 0
            || offset
                .checked_add(byte_size)
                .is_none_or(|end| end > self.byte_size)
        {
            return Err(SourceError::InvalidRange);
        }
        self.stamp.check(&self.file, self.byte_size)?;
        let expected_offset = u64::from(part_number - 1) * self.part_size;
        let expected_size = self.part_size.min(self.byte_size - offset);
        if offset != expected_offset || byte_size != expected_size {
            return Err(SourceError::InvalidRange);
        }
        let part = self
            .parts
            .get((part_number - 1) as usize)
            .ok_or(SourceError::InvalidRange)?;
        let file = Arc::clone(&self.file);
        let expected = part.sha256;
        let cancellation = tokio_util::sync::CancellationToken::new();
        let _cancel_on_drop = cancellation.clone().drop_guard();
        let actual = tokio::task::spawn_blocking(move || {
            hash_range(&file, offset, byte_size, &cancellation)
        })
        .await
        .map_err(|_| SourceError::Worker)??;
        if actual != expected {
            return Err(SourceError::DigestConflict);
        }
        self.stamp.check(&self.file, self.byte_size)?;

        let checksum = PartChecksum {
            algorithm,
            value: match algorithm {
                PartChecksumAlgorithm::Md5 => {
                    base64::engine::general_purpose::STANDARD.encode(part.md5)
                }
                PartChecksumAlgorithm::Sha256 => {
                    base64::engine::general_purpose::STANDARD.encode(part.sha256)
                }
            },
        };

        Ok(PartSource {
            source: self.clone(),
            identity: PartIdentity {
                part_number,
                offset,
                byte_size,
                sha256: hex::encode(part.sha256),
                checksum,
            },
        })
    }
}

/// Provider checksum algorithm selected by the admitted broker capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartChecksumAlgorithm {
    /// Padded base64 MD5 for the exact Content-MD5 header.
    Md5,
    /// Padded base64 SHA-256 for the exact x-amz-checksum-sha256 header.
    Sha256,
}

/// Exact checksum of one admitted source range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartChecksum {
    /// Provider checksum algorithm.
    pub algorithm: PartChecksumAlgorithm,
    /// Canonical padded standard base64 digest.
    pub value: String,
}

/// Exact source range identity supplied to a protocol adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartIdentity {
    /// One-based admitted part number.
    pub part_number: u32,
    /// Position-independent full-object offset.
    pub offset: u64,
    /// Exact request Content-Length.
    pub byte_size: u64,
    /// Lowercase SHA-256 of these bytes.
    pub sha256: String,
    /// Provider-enforced checksum for these bytes.
    pub checksum: PartChecksum,
}

/// A replayable part stream whose application buffers are at most 64 KiB.
#[derive(Clone)]
pub struct PartSource {
    source: AdmittedSource,
    identity: PartIdentity,
}

impl fmt::Debug for PartSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PartSource")
            .field("identity", &self.identity)
            .field("descriptor", &"[REDACTED]")
            .finish()
    }
}

impl PartSource {
    /// Returns the original whole-object identity and immutable geometry.
    pub fn source(&self) -> &AdmittedSource {
        &self.source
    }

    /// Returns the exact identity to which the provider grant must bind.
    pub fn identity(&self) -> &PartIdentity {
        &self.identity
    }

    /// Starts a fresh independent stream over the exact admitted range.
    ///
    /// Stream errors are value-free. A changed digest fails before yielding the
    /// final chunk; earlier chunks may already have reached the provider. This
    /// does not replace provider checksum enforcement or Worker full-object SHA.
    pub fn stream(&self) -> Pin<Box<dyn Stream<Item = Result<Bytes, io::Error>> + Send>> {
        let state = StreamState {
            source: self.clone(),
            consumed: 0,
            digests: Digests::new(),
        };
        Box::pin(stream::try_unfold(state, |mut state| async move {
            let remaining = state.source.identity.byte_size - state.consumed;
            if remaining == 0 {
                return Ok(None);
            }
            if state.consumed == 0 {
                state
                    .source
                    .source
                    .stamp
                    .check(&state.source.source.file, state.source.source.byte_size)
                    .map_err(io::Error::other)?;
            }
            let length = remaining.min(SOURCE_CHUNK_BYTES as u64) as usize;
            let offset = state.source.identity.offset + state.consumed;
            let file = Arc::clone(&state.source.source.file);
            let bytes = tokio::task::spawn_blocking(move || read_chunk(&file, offset, length))
                .await
                .map_err(|_| io::Error::other(SourceError::Worker))?
                .map_err(io::Error::other)?;
            state.digests.update(&bytes);
            state.consumed += bytes.len() as u64;

            if state.consumed == state.source.identity.byte_size {
                state
                    .source
                    .source
                    .stamp
                    .check(&state.source.source.file, state.source.source.byte_size)
                    .map_err(io::Error::other)?;
                let actual = state
                    .digests
                    .finish(state.source.identity.checksum.algorithm);
                if actual.sha256 != state.source.identity.sha256
                    || actual.checksum != state.source.identity.checksum
                {
                    return Err(io::Error::other(SourceError::DigestConflict));
                }
                // The completed state is never read again, but keeps a valid
                // accumulator so the stream remains a regular state machine.
                state.digests = Digests::new();
            }
            Ok(Some((Bytes::from(bytes), state)))
        }))
    }
}

struct StreamState {
    source: PartSource,
    consumed: u64,
    digests: Digests,
}

struct RangeDigest {
    sha256: String,
    checksum: PartChecksum,
}

struct HashCatalog {
    sha256: String,
    parts: Vec<HashedPart>,
}

struct HashedPart {
    sha256: [u8; 32],
    md5: [u8; 16],
}

struct Digests {
    sha256: sha2::Sha256,
    md5: md5::Md5,
}

impl Digests {
    fn new() -> Self {
        Self {
            sha256: sha2::Sha256::new(),
            md5: md5::Md5::new(),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.sha256.update(bytes);
        self.md5.update(bytes);
    }

    fn finish(self, algorithm: PartChecksumAlgorithm) -> RangeDigest {
        let part = self.finish_all();
        let value = match algorithm {
            PartChecksumAlgorithm::Md5 => {
                base64::engine::general_purpose::STANDARD.encode(part.md5)
            }
            PartChecksumAlgorithm::Sha256 => {
                base64::engine::general_purpose::STANDARD.encode(part.sha256)
            }
        };
        RangeDigest {
            sha256: hex::encode(part.sha256),
            checksum: PartChecksum { algorithm, value },
        }
    }

    fn finish_all(self) -> HashedPart {
        HashedPart {
            sha256: self.sha256.finalize().into(),
            md5: self.md5.finalize().into(),
        }
    }
}

fn canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hash_source(
    file: &File,
    mut remaining: u64,
    part_size: u64,
    cancellation: &tokio_util::sync::CancellationToken,
) -> Result<HashCatalog, SourceError> {
    let mut whole_sha256 = sha2::Sha256::new();
    let part_count = usize::try_from(remaining.div_ceil(part_size))
        .map_err(|_| SourceError::InvalidDeclaration)?;
    let mut parts = Vec::with_capacity(part_count);
    let mut offset = 0;
    let mut buffer = vec![0; SOURCE_CHUNK_BYTES];
    while remaining > 0 {
        let mut part_remaining = remaining.min(part_size);
        let mut digests = Digests::new();
        while part_remaining > 0 {
            if cancellation.is_cancelled() {
                return Err(SourceError::Cancelled);
            }
            let length = part_remaining.min(SOURCE_CHUNK_BYTES as u64) as usize;
            crate::multipart::read_descriptor_exact_at(file, &mut buffer[..length], offset)
                .map_err(|_| SourceError::Read)?;
            digests.update(&buffer[..length]);
            whole_sha256.update(&buffer[..length]);
            offset += length as u64;
            remaining -= length as u64;
            part_remaining -= length as u64;
        }
        parts.push(digests.finish_all());
    }
    Ok(HashCatalog {
        sha256: hex::encode(whole_sha256.finalize()),
        parts,
    })
}

fn hash_range(
    file: &File,
    mut offset: u64,
    mut remaining: u64,
    cancellation: &tokio_util::sync::CancellationToken,
) -> Result<[u8; 32], SourceError> {
    let mut digest = sha2::Sha256::new();
    let mut buffer = [0_u8; SOURCE_CHUNK_BYTES];
    while remaining > 0 {
        if cancellation.is_cancelled() {
            return Err(SourceError::Cancelled);
        }
        let count = remaining.min(SOURCE_CHUNK_BYTES as u64) as usize;
        crate::multipart::read_descriptor_exact_at(file, &mut buffer[..count], offset)
            .map_err(|_| SourceError::Read)?;
        digest.update(&buffer[..count]);
        offset += count as u64;
        remaining -= count as u64;
    }
    Ok(digest.finalize().into())
}

fn read_chunk(file: &File, offset: u64, length: usize) -> Result<Vec<u8>, SourceError> {
    let mut bytes = vec![0; length];
    crate::multipart::read_descriptor_exact_at(file, &mut bytes, offset)
        .map_err(|_| SourceError::Read)?;
    Ok(bytes)
}

// Descriptor metadata is a conservative early mutation fence, not protection
// against a writer retaining the same-owner source authority. Original hashes
// and provider-side whole-object verification still decide byte correctness.
#[derive(Clone, PartialEq, Eq)]
struct SourceStamp {
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    unix: (u64, u64, i64, i64, i64, i64),
}

impl SourceStamp {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt as _;
        Self {
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            unix: (
                metadata.dev(),
                metadata.ino(),
                metadata.mtime(),
                metadata.mtime_nsec(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            ),
        }
    }

    fn check(&self, file: &File, byte_size: u64) -> Result<(), SourceError> {
        let metadata = file.metadata().map_err(|_| SourceError::Read)?;
        if !metadata.is_file() || metadata.len() != byte_size {
            return Err(SourceError::SizeConflict);
        }
        if Self::from_metadata(&metadata) != *self {
            return Err(SourceError::IdentityConflict);
        }
        Ok(())
    }
}

/// A descriptor wave bounded by checksum catalogue allocations, not file size.
///
/// This budget admits at most64 files and32 MiB of fixed-width part catalogues.
/// Each part stores exactly32 SHA bytes and16 MD5 bytes, with an exactly-sized
/// vector. Descriptors and SHA strings add a small bounded allocation per file.
/// Whole file bodies stay on disk;32 provider streams each hold at most64 KiB
/// of application payload. TLS, HTTP and allocator overhead remain separate.
#[derive(Debug, Default)]
pub struct SourceWaveBudget {
    files: usize,
    catalogue_bytes: usize,
}

impl SourceWaveBudget {
    /// Reserves one declaration without reading or allocating its catalogue.
    ///
    /// A false result leaves this budget unchanged so the caller can dispatch
    /// its current wave before reserving in a new wave. Empty files use no parts.
    ///
    /// # Errors
    /// Rejects unsupported source sizes, part geometry or arithmetic overflow.
    pub fn reserve(&mut self, byte_size: u64, part_size: u64) -> Result<bool, SourceError> {
        if byte_size > MAX_SOURCE_BYTES || part_size == 0 || part_size > 64 * 1024 * 1024 {
            return Err(SourceError::InvalidDeclaration);
        }
        let count = usize::try_from(byte_size.div_ceil(part_size))
            .map_err(|_| SourceError::InvalidDeclaration)?;
        if count > 10_000 {
            return Err(SourceError::InvalidDeclaration);
        }
        let bytes = count
            .checked_mul(std::mem::size_of::<HashedPart>())
            .ok_or(SourceError::InvalidDeclaration)?;
        let total = self
            .catalogue_bytes
            .checked_add(bytes)
            .ok_or(SourceError::InvalidDeclaration)?;
        if self.files == 64 || total > 32 * 1024 * 1024 {
            return Ok(false);
        }
        self.files += 1;
        self.catalogue_bytes = total;
        Ok(true)
    }

    /// Returns the reserved fixed-width catalogue payload allocation.
    pub fn catalogue_bytes(&self) -> usize {
        self.catalogue_bytes
    }
}
