//! Canonical root and physical-candidate manifests for campaign GC plans.
//!
//! Both formats are streamed and entry-bounded rather than wrapped in one
//! content-store envelope. This keeps plan evidence outside the store whose
//! generation it authenticates and avoids making plan publication invalidate
//! its own physical-inventory basis.
//!
//! A manifest value is a handle to its canonical file, never a resident copy
//! of its entries: opening a file validates it in one streaming pass and
//! records only its identity and counters, and each iteration reads the file
//! again. Planning writes manifests straight into private scratch files, and
//! a journal holds handles to its own durable copies, so neither holds up to
//! [`MAX_CAMPAIGN_GC_MANIFEST_ENTRIES`] entries in memory.
//!
//! The root format is:
//!
//! ```text
//! "crucible.campaign.gc-root-manifest.v1\0"
//! root_count:u64be
//! repeated root_count times in strict (kind tag, schema version, digest) order:
//!   content_id_length:u16be || content_id_utf8
//! ```
//!
//! The candidate format is:
//!
//! ```text
//! "crucible.campaign.gc-candidate-manifest.v1\0"
//! candidate_count:u64be
//! repeated candidate_count times in strict
//! (backend, kind tag, schema version, digest) order:
//!   backend_length:u16be || backend_utf8
//!   content_id_length:u16be || content_id_utf8
//!   logical_length:u64be
//!   reason:u8 # 0 unreachable, 1 reachable cache
//!   if reason == 1:
//!     required_backend_length:u16be || required_backend_utf8
//! ```

mod codec;

use std::cmp::Ordering;
use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crucible_campaign::CampaignHash;
use crucible_store::content_store::ContentId;
use thiserror::Error;

use super::spill::GcWorkDirectory;
use super::{
    CampaignGcCandidateSetId, CampaignGcCandidateSetSummary, CampaignGcRootSetId,
    MAX_CAMPAIGN_GC_BACKEND_ID_BYTES, MAX_CAMPAIGN_GC_PHYSICAL_INVENTORIES, validate_backend_id,
};
use codec::{
    CountingReader, PendingManifest, hash_bounded_string, hash_candidate, manifest_hasher,
    next_entry_count, read_candidate, read_count, read_ordered_root, require_eof, require_magic,
    write_bounded_string, write_candidate,
};

const ROOT_MANIFEST_MAGIC: &[u8] = b"crucible.campaign.gc-root-manifest.v1\0";
const ROOT_MANIFEST_HASH_DOMAIN: &[u8] = b"crucible.campaign.gc-root-manifest.v1";
const CANDIDATE_MANIFEST_MAGIC: &[u8] = b"crucible.campaign.gc-candidate-manifest.v1\0";
const CANDIDATE_MANIFEST_HASH_DOMAIN: &[u8] = b"crucible.campaign.gc-candidate-manifest.v1";
const MAX_CONTENT_ID_BYTES: usize = 128;
const IO_BUFFER_BYTES: usize = 64 * 1024;

/// Maximum number of roots or physical placements in one local manifest.
///
/// This is a format bound: writers reject an additional entry once it is
/// reached, but entries are streamed to disk and never held in memory
/// together. Repository closure walks have no matching whole-closure bound;
/// they authenticate one transition delta at a time.
pub const MAX_CAMPAIGN_GC_MANIFEST_ENTRIES: usize = 64_000_000;

/// Canonical manifest file and the scratch directory that owns it, if any.
///
/// A durable journal copy has no owner and outlives the handle. A planning
/// copy keeps its private work directory alive and goes away with it.
#[derive(Debug)]
struct ManifestFile {
    path: PathBuf,
    _owner: Option<Arc<GcWorkDirectory>>,
}

impl ManifestFile {
    fn open_reader(&self) -> Result<CountingReader, CampaignGcManifestError> {
        Ok(CountingReader::new(File::open(&self.path)?))
    }
}

/// Exact sorted set of logical roots used for reachability planning.
///
/// Clones share the backing file. Two manifests are equal when their
/// canonical identities and counts are equal.
#[derive(Clone, Debug)]
pub struct CampaignGcRootManifest {
    file: Arc<ManifestFile>,
    roots: u64,
    id: CampaignGcRootSetId,
}

impl PartialEq for CampaignGcRootManifest {
    fn eq(&self, other: &Self) -> bool {
        self.roots == other.roots && self.id == other.id
    }
}

impl Eq for CampaignGcRootManifest {}

impl CampaignGcRootManifest {
    /// Opens and strictly validates one canonical v1 root manifest file.
    ///
    /// The file is read once to compute its identity; the entries are not
    /// retained.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcManifestError`] for I/O failure, unsupported magic,
    /// excessive count, malformed IDs, noncanonical order, or trailing bytes.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, CampaignGcManifestError> {
        Self::open_owned(path.into(), None)
    }

    fn open_owned(
        path: PathBuf,
        owner: Option<Arc<GcWorkDirectory>>,
    ) -> Result<Self, CampaignGcManifestError> {
        let file = Arc::new(ManifestFile {
            path,
            _owner: owner,
        });
        let mut reader = file.open_reader()?;
        require_magic(&mut reader, ROOT_MANIFEST_MAGIC)?;
        let roots = read_count(&mut reader)?;

        let mut hasher = manifest_hasher(ROOT_MANIFEST_HASH_DOMAIN);
        hasher.update(ROOT_MANIFEST_MAGIC);
        hasher.update(&roots.to_be_bytes());
        let mut previous = None;
        for _ in 0..roots {
            let root = read_ordered_root(&mut reader, &mut previous)?;
            hash_bounded_string(&mut hasher, &root.encode());
        }
        require_eof(&mut reader)?;

        let id =
            CampaignGcRootSetId::from_hash(CampaignHash::from_bytes(*hasher.finalize().as_bytes()));
        Ok(Self { file, roots, id })
    }

    /// Returns the exact manifest identity.
    #[must_use]
    pub const fn id(&self) -> CampaignGcRootSetId {
        self.id
    }

    /// Returns the number of unique logical roots.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.roots
    }

    /// Returns whether the manifest contains no roots.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.roots == 0
    }

    /// Returns the path of the backing canonical file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.file.path
    }

    /// Streams roots in their canonical order from the backing file.
    ///
    /// The iterator re-derives the manifest identity as it reads. If the file
    /// changed after it was opened, the last entry is replaced by
    /// [`CampaignGcManifestError::Changed`], so a caller that consumes the
    /// whole stream before acting never acts on substituted content.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcManifestError`] when the file cannot be reopened
    /// or no longer starts with the validated header. Entry errors are
    /// yielded by the iterator, which then stops.
    pub fn iter(&self) -> Result<CampaignGcRootManifestEntries, CampaignGcManifestError> {
        let mut reader = self.file.open_reader()?;
        require_magic(&mut reader, ROOT_MANIFEST_MAGIC)?;
        if read_count(&mut reader)? != self.roots {
            return Err(CampaignGcManifestError::Changed);
        }
        let mut hasher = manifest_hasher(ROOT_MANIFEST_HASH_DOMAIN);
        hasher.update(ROOT_MANIFEST_MAGIC);
        hasher.update(&self.roots.to_be_bytes());
        Ok(CampaignGcRootManifestEntries {
            reader,
            remaining: self.roots,
            previous: None,
            hasher,
            expected: self.id,
        })
    }

    /// Reports whether `id` is one of the manifest's roots.
    ///
    /// This is a streaming scan of the backing file.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcManifestError`] when the file cannot be read back.
    pub fn contains(&self, id: ContentId) -> Result<bool, CampaignGcManifestError> {
        for root in self.iter()? {
            match compare_content_id(root?, id) {
                Ordering::Less => {}
                Ordering::Equal => return Ok(true),
                Ordering::Greater => return Ok(false),
            }
        }
        Ok(false)
    }

    /// Streams this manifest's exact canonical representation.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcManifestError::Io`] if the backing file cannot be
    /// read or the destination rejects any bytes.
    pub fn write_canonical(&self, writer: &mut dyn Write) -> Result<(), CampaignGcManifestError> {
        io::copy(&mut File::open(&self.file.path)?, writer)?;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn from_roots_for_test(
        directory: &Arc<GcWorkDirectory>,
        roots: impl IntoIterator<Item = ContentId>,
    ) -> Result<Self, CampaignGcManifestError> {
        let mut roots = roots.into_iter().collect::<Vec<_>>();
        roots.sort_by(|left, right| compare_content_id(*left, *right));
        roots.dedup();
        let mut writer = CampaignGcRootManifestWriter::create(directory)?;
        for root in roots {
            writer.push(root)?;
        }
        writer.finish()
    }
}

/// Streaming reader over one root manifest's entries.
pub struct CampaignGcRootManifestEntries {
    reader: CountingReader,
    remaining: u64,
    previous: Option<ContentId>,
    hasher: blake3::Hasher,
    expected: CampaignGcRootSetId,
}

impl CampaignGcRootManifestEntries {
    fn read_next(&mut self) -> Result<ContentId, CampaignGcManifestError> {
        let root = read_ordered_root(&mut self.reader, &mut self.previous)?;
        hash_bounded_string(&mut self.hasher, &root.encode());
        if self.remaining == 1 {
            require_eof(&mut self.reader).map_err(|_| CampaignGcManifestError::Changed)?;
            let actual = CampaignGcRootSetId::from_hash(CampaignHash::from_bytes(
                *self.hasher.finalize().as_bytes(),
            ));
            if actual != self.expected {
                return Err(CampaignGcManifestError::Changed);
            }
        }
        Ok(root)
    }
}

impl std::fmt::Debug for CampaignGcRootManifestEntries {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CampaignGcRootManifestEntries")
            .field("remaining", &self.remaining)
            .finish_non_exhaustive()
    }
}

impl Iterator for CampaignGcRootManifestEntries {
    type Item = Result<ContentId, CampaignGcManifestError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let root = self.read_next();
        // An error ends the stream so a caller never resumes mid-entry.
        self.remaining = if root.is_ok() { self.remaining - 1 } else { 0 };
        Some(root)
    }
}

/// Streaming writer for one root manifest in a private work directory.
///
/// Roots must arrive in strict canonical order. The count is patched in
/// after the last entry, and the finished file is reopened and validated.
pub(super) struct CampaignGcRootManifestWriter {
    output: PendingManifest,
    roots: u64,
    previous: Option<ContentId>,
}

impl CampaignGcRootManifestWriter {
    pub(super) fn create(
        directory: &Arc<GcWorkDirectory>,
    ) -> Result<Self, CampaignGcManifestError> {
        Ok(Self {
            output: PendingManifest::create(directory, "roots", ROOT_MANIFEST_MAGIC)?,
            roots: 0,
            previous: None,
        })
    }

    pub(super) fn push(&mut self, root: ContentId) -> Result<(), CampaignGcManifestError> {
        if self
            .previous
            .is_some_and(|prior| compare_content_id(prior, root) != Ordering::Less)
        {
            return Err(CampaignGcManifestError::Noncanonical);
        }
        self.roots = next_entry_count(self.roots)?;
        write_bounded_string(
            &mut self.output.writer,
            &root.encode(),
            MAX_CONTENT_ID_BYTES,
        )?;
        self.previous = Some(root);
        Ok(())
    }

    pub(super) fn finish(self) -> Result<CampaignGcRootManifest, CampaignGcManifestError> {
        let (path, owner) = self.output.seal(self.roots)?;
        CampaignGcRootManifest::open_owned(path, Some(owner))
    }
}

/// One exact physical logical-object placement approved for deletion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignGcCandidate {
    backend: String,
    id: ContentId,
    logical_length: u64,
    reason: CampaignGcCandidateReason,
}

/// Exact policy reason authorizing one physical candidate deletion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CampaignGcCandidateReason {
    /// The logical object is absent from the authenticated reachable closure.
    Unreachable,
    /// A reachable cache copy is backed by an independent required copy.
    ReachableCache {
        /// Physical backend whose plan basis authenticates the required copy.
        required_backend: String,
    },
}

impl CampaignGcCandidate {
    /// Builds one validated physical candidate entry.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcManifestError::InvalidBackendId`] if `backend`
    /// violates the frozen operational identifier grammar.
    pub fn new(
        backend: impl Into<String>,
        id: ContentId,
        logical_length: u64,
    ) -> Result<Self, CampaignGcManifestError> {
        let backend = backend.into();
        validate_backend_id(&backend).map_err(|_| CampaignGcManifestError::InvalidBackendId)?;
        Ok(Self {
            backend,
            id,
            logical_length,
            reason: CampaignGcCandidateReason::Unreachable,
        })
    }

    /// Builds one reachable cache candidate and required-copy basis.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcManifestError::InvalidBackendId`] if either backend
    /// violates the operational identifier grammar, or
    /// [`CampaignGcManifestError::InvalidField`] if both names are equal.
    pub fn new_reachable_cache(
        backend: impl Into<String>,
        id: ContentId,
        logical_length: u64,
        required_backend: impl Into<String>,
    ) -> Result<Self, CampaignGcManifestError> {
        let backend = backend.into();
        let required_backend = required_backend.into();
        validate_backend_id(&backend).map_err(|_| CampaignGcManifestError::InvalidBackendId)?;
        validate_backend_id(&required_backend)
            .map_err(|_| CampaignGcManifestError::InvalidBackendId)?;
        if backend == required_backend {
            return Err(CampaignGcManifestError::InvalidField);
        }
        Ok(Self {
            backend,
            id,
            logical_length,
            reason: CampaignGcCandidateReason::ReachableCache { required_backend },
        })
    }

    /// Returns the exact physical backend identifier.
    #[must_use]
    pub fn backend(&self) -> &str {
        &self.backend
    }

    /// Returns the logical content identity of the placement.
    #[must_use]
    pub const fn id(&self) -> ContentId {
        self.id
    }

    /// Returns the inventoried physical logical length.
    #[must_use]
    pub const fn logical_length(&self) -> u64 {
        self.logical_length
    }

    /// Returns the exact policy reason and required-copy reference.
    #[must_use]
    pub const fn reason(&self) -> &CampaignGcCandidateReason {
        &self.reason
    }
}

/// Byte range of one backend's contiguous candidates in a manifest file.
#[derive(Clone, Debug)]
struct BackendRange {
    backend: String,
    offset: u64,
    candidates: u64,
}

/// Canonical ordered physical-deletion candidate manifest.
///
/// Clones share the backing file. Besides its identity and counters the
/// handle keeps one byte range per physical backend, bounded by the plan's
/// physical inventory limit, so one backend's candidates can be streamed
/// without scanning the others. Two manifests are equal when their
/// canonical summaries and reason counts are equal.
#[derive(Clone, Debug)]
pub struct CampaignGcCandidateManifest {
    file: Arc<ManifestFile>,
    summary: CampaignGcCandidateSetSummary,
    unreachable_candidates: u64,
    reachable_cache_candidates: u64,
    backends: Vec<BackendRange>,
}

impl PartialEq for CampaignGcCandidateManifest {
    fn eq(&self, other: &Self) -> bool {
        self.summary == other.summary
            && self.unreachable_candidates == other.unreachable_candidates
            && self.reachable_cache_candidates == other.reachable_cache_candidates
    }
}

impl Eq for CampaignGcCandidateManifest {}

impl CampaignGcCandidateManifest {
    /// Opens and strictly validates one canonical candidate manifest file.
    ///
    /// The file is read once to compute its summary and per-backend ranges;
    /// the entries are not retained.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcManifestError`] for I/O failure, unsupported magic,
    /// excessive count, malformed fields, noncanonical order, duplicate
    /// placements, more backends than a plan may bind, accounting overflow,
    /// or trailing bytes.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, CampaignGcManifestError> {
        Self::open_owned(path.into(), None)
    }

    fn open_owned(
        path: PathBuf,
        owner: Option<Arc<GcWorkDirectory>>,
    ) -> Result<Self, CampaignGcManifestError> {
        let file = Arc::new(ManifestFile {
            path,
            _owner: owner,
        });
        let mut reader = file.open_reader()?;
        require_magic(&mut reader, CANDIDATE_MANIFEST_MAGIC)?;
        let count = read_count(&mut reader)?;

        let mut hasher = manifest_hasher(CANDIDATE_MANIFEST_HASH_DOMAIN);
        hasher.update(CANDIDATE_MANIFEST_MAGIC);
        hasher.update(&count.to_be_bytes());
        let mut logical_bytes = 0_u64;
        let mut unreachable_candidates = 0_u64;
        let mut backends = Vec::<BackendRange>::new();
        let mut previous = None;
        for _ in 0..count {
            let offset = reader.position();
            let candidate = read_candidate(&mut reader)?;
            check_candidate_order(previous.as_ref(), &candidate)?;
            hash_candidate(&mut hasher, &candidate);

            logical_bytes = logical_bytes
                .checked_add(candidate.logical_length)
                .ok_or(CampaignGcManifestError::CountOverflow)?;
            if candidate.reason == CampaignGcCandidateReason::Unreachable {
                unreachable_candidates += 1;
            }
            match backends.last_mut() {
                Some(range) if range.backend == candidate.backend => range.candidates += 1,
                _ => {
                    if backends.len() >= MAX_CAMPAIGN_GC_PHYSICAL_INVENTORIES {
                        return Err(CampaignGcManifestError::BackendLimit);
                    }
                    backends.push(BackendRange {
                        backend: candidate.backend.clone(),
                        offset,
                        candidates: 1,
                    });
                }
            }
            previous = Some(candidate);
        }
        require_eof(&mut reader)?;

        let id = CampaignGcCandidateSetId::from_hash(CampaignHash::from_bytes(
            *hasher.finalize().as_bytes(),
        ));
        Ok(Self {
            file,
            summary: CampaignGcCandidateSetSummary::new(id, count, logical_bytes),
            unreachable_candidates,
            reachable_cache_candidates: count - unreachable_candidates,
            backends,
        })
    }

    /// Returns the exact manifest identity and terminal counters.
    #[must_use]
    pub const fn summary(&self) -> CampaignGcCandidateSetSummary {
        self.summary
    }

    /// Returns the number of physical candidates.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.summary.candidates()
    }

    /// Returns whether the candidate set is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.summary.candidates() == 0
    }

    /// Returns the checked total candidate logical bytes.
    #[must_use]
    pub const fn logical_bytes(&self) -> u64 {
        self.summary.logical_bytes()
    }

    /// Returns candidates authorized because their logical object is unreachable.
    #[must_use]
    pub const fn unreachable_candidates(&self) -> u64 {
        self.unreachable_candidates
    }

    /// Returns reachable cache candidates authorized by current policy.
    #[must_use]
    pub const fn reachable_cache_candidates(&self) -> u64 {
        self.reachable_cache_candidates
    }

    /// Returns the path of the backing canonical file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.file.path
    }

    /// Streams candidates in canonical physical order from the backing file.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcManifestError`] when the file cannot be reopened
    /// or no longer starts with the validated header. Entry errors are
    /// yielded by the iterator, which then stops.
    pub fn iter(&self) -> Result<CampaignGcCandidateManifestEntries, CampaignGcManifestError> {
        let mut reader = self.file.open_reader()?;
        require_magic(&mut reader, CANDIDATE_MANIFEST_MAGIC)?;
        if read_count(&mut reader)? != self.len() {
            return Err(CampaignGcManifestError::Changed);
        }
        let mut hasher = manifest_hasher(CANDIDATE_MANIFEST_HASH_DOMAIN);
        hasher.update(CANDIDATE_MANIFEST_MAGIC);
        hasher.update(&self.len().to_be_bytes());
        Ok(CampaignGcCandidateManifestEntries {
            reader,
            remaining: self.len(),
            backend: None,
            previous: None,
            verify: Some((hasher, self.summary.id())),
        })
    }

    /// Returns the number of candidates on one physical backend.
    pub(super) fn backend_candidates(&self, backend: &str) -> u64 {
        self.backend_range(backend)
            .map_or(0, |range| range.candidates)
    }

    /// Streams one backend's candidates in canonical identity order.
    pub(super) fn iter_backend(
        &self,
        backend: &str,
    ) -> Result<CampaignGcCandidateManifestEntries, CampaignGcManifestError> {
        let Some(range) = self.backend_range(backend) else {
            return Ok(CampaignGcCandidateManifestEntries {
                reader: self.file.open_reader()?,
                remaining: 0,
                backend: None,
                previous: None,
                verify: None,
            });
        };
        let mut file = File::open(&self.file.path)?;
        file.seek(SeekFrom::Start(range.offset))?;
        Ok(CampaignGcCandidateManifestEntries {
            reader: CountingReader::new(file),
            remaining: range.candidates,
            backend: Some(range.backend.clone()),
            previous: None,
            verify: None,
        })
    }

    /// Streams this candidate manifest's exact canonical representation.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcManifestError::Io`] if the backing file cannot be
    /// read or the destination rejects any bytes.
    pub fn write_canonical(&self, writer: &mut dyn Write) -> Result<(), CampaignGcManifestError> {
        io::copy(&mut File::open(&self.file.path)?, writer)?;
        Ok(())
    }

    fn backend_range(&self, backend: &str) -> Option<&BackendRange> {
        self.backends
            .binary_search_by(|range| range.backend.as_str().cmp(backend))
            .ok()
            .map(|index| &self.backends[index])
    }

    #[cfg(test)]
    pub(super) fn from_candidates_for_test(
        directory: &Arc<GcWorkDirectory>,
        mut candidates: Vec<CampaignGcCandidate>,
    ) -> Result<Self, CampaignGcManifestError> {
        candidates.sort_by(compare_candidate);
        let mut writer = CampaignGcCandidateManifestWriter::create(directory)?;
        for candidate in &candidates {
            writer.push(candidate)?;
        }
        writer.finish()
    }
}

/// Streaming reader over a candidate manifest or one backend's range of it.
///
/// A full-manifest reader re-derives the manifest identity and replaces its
/// last entry with [`CampaignGcManifestError::Changed`] if the file changed
/// after it was opened. A single backend's range is checked for order and
/// backend only.
pub struct CampaignGcCandidateManifestEntries {
    reader: CountingReader,
    remaining: u64,
    backend: Option<String>,
    previous: Option<CampaignGcCandidate>,
    verify: Option<(blake3::Hasher, CampaignGcCandidateSetId)>,
}

impl std::fmt::Debug for CampaignGcCandidateManifestEntries {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CampaignGcCandidateManifestEntries")
            .field("remaining", &self.remaining)
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}

impl CampaignGcCandidateManifestEntries {
    fn read_next(&mut self) -> Result<CampaignGcCandidate, CampaignGcManifestError> {
        let candidate = read_candidate(&mut self.reader)?;
        check_candidate_order(self.previous.as_ref(), &candidate)?;
        if self
            .backend
            .as_deref()
            .is_some_and(|backend| backend != candidate.backend)
        {
            return Err(CampaignGcManifestError::Noncanonical);
        }
        if let Some((hasher, expected)) = self.verify.as_mut() {
            hash_candidate(hasher, &candidate);
            if self.remaining == 1 {
                require_eof(&mut self.reader).map_err(|_| CampaignGcManifestError::Changed)?;
                let actual = CampaignGcCandidateSetId::from_hash(CampaignHash::from_bytes(
                    *hasher.finalize().as_bytes(),
                ));
                if actual != *expected {
                    return Err(CampaignGcManifestError::Changed);
                }
            }
        }
        self.previous = Some(candidate.clone());
        Ok(candidate)
    }
}

impl Iterator for CampaignGcCandidateManifestEntries {
    type Item = Result<CampaignGcCandidate, CampaignGcManifestError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let candidate = self.read_next();
        // An error ends the stream so a caller never resumes mid-entry.
        self.remaining = if candidate.is_ok() {
            self.remaining - 1
        } else {
            0
        };
        Some(candidate)
    }
}

/// Streaming writer for one candidate manifest in a private work directory.
///
/// Candidates must arrive in strict canonical (backend, identity) order.
pub(super) struct CampaignGcCandidateManifestWriter {
    output: PendingManifest,
    candidates: u64,
    logical_bytes: u64,
    previous: Option<CampaignGcCandidate>,
}

impl CampaignGcCandidateManifestWriter {
    pub(super) fn create(
        directory: &Arc<GcWorkDirectory>,
    ) -> Result<Self, CampaignGcManifestError> {
        Ok(Self {
            output: PendingManifest::create(directory, "candidates", CANDIDATE_MANIFEST_MAGIC)?,
            candidates: 0,
            logical_bytes: 0,
            previous: None,
        })
    }

    pub(super) fn push(
        &mut self,
        candidate: &CampaignGcCandidate,
    ) -> Result<(), CampaignGcManifestError> {
        check_candidate_order(self.previous.as_ref(), candidate)?;
        self.candidates = next_entry_count(self.candidates)?;
        self.logical_bytes = self
            .logical_bytes
            .checked_add(candidate.logical_length)
            .ok_or(CampaignGcManifestError::CountOverflow)?;
        write_candidate(&mut self.output.writer, candidate)?;
        self.previous = Some(candidate.clone());
        Ok(())
    }

    pub(super) fn finish(self) -> Result<CampaignGcCandidateManifest, CampaignGcManifestError> {
        let (path, owner) = self.output.seal(self.candidates)?;
        CampaignGcCandidateManifest::open_owned(path, Some(owner))
    }
}

/// Failure to construct, encode, or decode a canonical GC manifest.
#[derive(Debug, Error)]
pub enum CampaignGcManifestError {
    /// A manifest contains more entries than the fixed work bound.
    #[error("campaign GC manifest entry limit exceeded")]
    EntryLimit,
    /// A candidate manifest names more physical backends than a plan may bind.
    #[error("campaign GC candidate manifest names too many physical backends")]
    BackendLimit,
    /// A physical backend identifier violates the fixed grammar.
    #[error("campaign GC manifest backend identifier is invalid")]
    InvalidBackendId,
    /// The same physical backend and content identity occurs more than once.
    #[error("campaign GC manifest contains a duplicate physical candidate")]
    DuplicateCandidate,
    /// A terminal count or byte sum overflowed.
    #[error("campaign GC manifest count overflow")]
    CountOverflow,
    /// A manifest field or content identity is malformed.
    #[error("campaign GC manifest field is invalid")]
    InvalidField,
    /// The manifest magic or version is unsupported.
    #[error("campaign GC manifest schema is unsupported")]
    UnsupportedSchema,
    /// Entries are duplicated, unordered, or have an alternate representation.
    #[error("campaign GC manifest encoding is noncanonical")]
    Noncanonical,
    /// The backing file no longer matches the identity validated at open.
    #[error("campaign GC manifest file changed after it was opened")]
    Changed,
    /// The canonical stream is truncated, unreadable, or unwritable.
    #[error("campaign GC manifest I/O failed")]
    Io(#[from] io::Error),
}

pub(super) fn compare_candidate(
    left: &CampaignGcCandidate,
    right: &CampaignGcCandidate,
) -> Ordering {
    left.backend
        .cmp(&right.backend)
        .then_with(|| compare_content_id(left.id, right.id))
}

pub(super) fn compare_content_id(left: ContentId, right: ContentId) -> Ordering {
    left.kind()
        .as_str()
        .cmp(right.kind().as_str())
        .then_with(|| left.schema_version().cmp(&right.schema_version()))
        .then_with(|| left.digest().cmp(&right.digest()))
}

fn check_candidate_order(
    previous: Option<&CampaignGcCandidate>,
    candidate: &CampaignGcCandidate,
) -> Result<(), CampaignGcManifestError> {
    match previous.map(|prior| compare_candidate(prior, candidate)) {
        None | Some(Ordering::Less) => Ok(()),
        Some(Ordering::Equal) => Err(CampaignGcManifestError::DuplicateCandidate),
        Some(Ordering::Greater) => Err(CampaignGcManifestError::Noncanonical),
    }
}
