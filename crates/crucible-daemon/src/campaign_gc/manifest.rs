//! Canonical root and physical-candidate manifests for campaign GC plans.
//!
//! Both formats are streamed and entry-bounded rather than wrapped in one
//! content-store envelope. This keeps plan evidence outside the store whose
//! generation it authenticates and avoids making plan publication invalidate
//! its own physical-inventory basis.
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

use std::cmp::Ordering;
use std::io::{self, Read, Write};
use std::sync::Arc;

use crucible_campaign::CampaignHash;
use crucible_cas::content_store::{ContentId, StoreError};
use thiserror::Error;

use super::{
    CampaignGcCandidateSetId, CampaignGcCandidateSetSummary, CampaignGcOperationContext,
    CampaignGcRootSetId, MAX_CAMPAIGN_GC_BACKEND_ID_BYTES, validate_backend_id,
};

const ROOT_MANIFEST_MAGIC: &[u8] = b"crucible.campaign.gc-root-manifest.v1\0";
const ROOT_MANIFEST_HASH_DOMAIN: &[u8] = b"crucible.campaign.gc-root-manifest.v1";
const CANDIDATE_MANIFEST_MAGIC: &[u8] = b"crucible.campaign.gc-candidate-manifest.v1\0";
const CANDIDATE_MANIFEST_HASH_DOMAIN: &[u8] = b"crucible.campaign.gc-candidate-manifest.v1";
const MAX_CONTENT_ID_BYTES: usize = 128;

/// Maximum number of roots or physical placements in one local manifest.
///
/// RAM graph traversal has a separate, larger work bound. Physical deletion
/// proceeds in batches so retained planning memory does not scale with RAM.
pub const MAX_CAMPAIGN_GC_MANIFEST_ENTRIES: usize = 65_536;

/// Clone-shared custody for one admitted immutable metadata allocation.
///
/// Equality deliberately compares semantic records rather than account identity.
#[derive(Clone)]
pub(super) struct MetadataCredit(crucible_cas::owned_decode::ResourceLoan);

impl std::fmt::Debug for MetadataCredit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = &self.0;
        formatter.write_str("MetadataCredit")
    }
}

impl PartialEq for MetadataCredit {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for MetadataCredit {}

impl MetadataCredit {
    pub(super) fn new(credit: crucible_cas::owned_decode::ResourceLoan) -> Self {
        Self(credit)
    }
}

/// Holds optional constructor custody without changing semantic record equality.
#[derive(Clone, Debug, Default)]
pub(super) struct OptionalMetadataCredit(Option<MetadataCredit>);

impl OptionalMetadataCredit {
    pub(super) fn new(credit: MetadataCredit) -> Self {
        Self(Some(credit))
    }
}

impl PartialEq for OptionalMetadataCredit {
    fn eq(&self, other: &Self) -> bool {
        let _ = (&self.0, &other.0);
        true
    }
}

impl Eq for OptionalMetadataCredit {}

fn reserve_vector<T>(
    operation: &CampaignGcOperationContext<'_>,
    count: usize,
) -> Result<MetadataCredit, CampaignGcManifestError> {
    let bytes = count
        .checked_mul(std::mem::size_of::<T>())
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<Vec<T>>() + 2 * std::mem::size_of::<usize>())
        })
        .ok_or(CampaignGcManifestError::CountOverflow)?;
    Ok(MetadataCredit::new(operation.reserve_bytes(
        u64::try_from(bytes).map_err(|_| CampaignGcManifestError::CountOverflow)?,
    )?))
}

fn allocate_vector<T>(count: usize) -> Result<Vec<T>, CampaignGcManifestError> {
    let mut entries = Vec::new();
    entries.try_reserve_exact(count).map_err(|source| {
        CampaignGcManifestError::Resources(StoreError::Supervision {
            source: Box::new(source),
        })
    })?;
    Ok(entries)
}

/// Exact sorted set of logical roots used for reachability planning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignGcRootManifest {
    roots: Arc<Vec<ContentId>>,
    _credit: MetadataCredit,
}

impl CampaignGcRootManifest {
    /// Builds a deduplicated canonical root manifest.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcManifestError::EntryLimit`] if more than the fixed
    /// v1 root bound is supplied.
    pub fn new<I>(
        roots: I,
        operation: &CampaignGcOperationContext<'_>,
    ) -> Result<Self, CampaignGcManifestError>
    where
        I: IntoIterator<Item = ContentId>,
        I::IntoIter: ExactSizeIterator,
    {
        let roots = roots.into_iter();
        let count = roots.len();
        if count > MAX_CAMPAIGN_GC_MANIFEST_ENTRIES {
            return Err(CampaignGcManifestError::EntryLimit);
        }
        let credit = reserve_vector::<ContentId>(operation, count)?;
        let mut canonical = allocate_vector(count)?;
        for root in roots {
            if canonical.len() == count {
                return Err(CampaignGcManifestError::EntryLimit);
            }
            canonical.push(root);
        }
        canonical.sort_unstable_by(|left, right| compare_content_id(*left, *right));
        canonical.dedup();
        Ok(Self {
            roots: Arc::new(canonical),
            _credit: credit,
        })
    }

    /// Strictly reads one canonical v1 root manifest.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcManifestError`] for I/O failure, unsupported magic,
    /// excessive count, malformed IDs, noncanonical order, or trailing bytes.
    pub fn from_canonical_reader(
        reader: &mut dyn Read,
        operation: &CampaignGcOperationContext<'_>,
    ) -> Result<Self, CampaignGcManifestError> {
        require_magic(reader, ROOT_MANIFEST_MAGIC)?;
        let count = read_count(reader)?;
        let _codec = operation
            .reserve_bytes((MAX_CONTENT_ID_BYTES + std::mem::size_of::<String>()) as u64)?;
        let credit = reserve_vector::<ContentId>(operation, count)?;
        let mut roots = allocate_vector(count)?;
        let mut previous = None;
        for _ in 0..count {
            let root = read_content_id(reader)?;
            if previous.is_some_and(|prior| compare_content_id(prior, root) != Ordering::Less) {
                return Err(CampaignGcManifestError::Noncanonical);
            }
            roots.push(root);
            previous = Some(root);
        }
        require_eof(reader)?;
        Ok(Self {
            roots: Arc::new(roots),
            _credit: credit,
        })
    }

    /// Streams the exact canonical v1 representation.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcManifestError::Io`] if the destination rejects any
    /// bytes. Construction already proves all length fields representable.
    pub fn write_canonical(&self, writer: &mut dyn Write) -> Result<(), CampaignGcManifestError> {
        writer.write_all(ROOT_MANIFEST_MAGIC)?;
        writer.write_all(&entry_count(self.roots.len())?.to_be_bytes())?;
        for root in self.roots.iter() {
            write_content_id(writer, *root)?;
        }
        Ok(())
    }

    /// Returns the exact manifest identity.
    #[must_use]
    pub fn id(&self) -> CampaignGcRootSetId {
        let mut hasher = manifest_hasher(ROOT_MANIFEST_HASH_DOMAIN);
        hasher.update(ROOT_MANIFEST_MAGIC);
        hasher.update(&(self.roots.len() as u64).to_be_bytes());
        for root in self.roots.iter() {
            hash_content_id(&mut hasher, *root);
        }
        CampaignGcRootSetId::from_hash(CampaignHash::from_bytes(*hasher.finalize().as_bytes()))
    }

    /// Returns the number of unique logical roots.
    #[must_use]
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Returns whether the manifest contains no roots.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Iterates roots in their canonical order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = ContentId> + '_ {
        self.roots.iter().copied()
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

    pub(super) fn compare_id(&self, id: ContentId) -> Ordering {
        compare_content_id(self.id, id)
    }
}

/// Canonical ordered physical-deletion candidate manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignGcCandidateManifest {
    candidates: Arc<Vec<CampaignGcCandidate>>,
    logical_bytes: u64,
    _credit: OptionalMetadataCredit,
}

impl CampaignGcCandidateManifest {
    /// Builds and canonically orders one candidate manifest.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcManifestError::EntryLimit`] for an excessive entry
    /// count, [`CampaignGcManifestError::DuplicateCandidate`] for the same
    /// physical placement twice, or [`CampaignGcManifestError::CountOverflow`]
    /// if logical byte accounting overflows.
    pub fn new(mut candidates: Vec<CampaignGcCandidate>) -> Result<Self, CampaignGcManifestError> {
        if candidates.len() > MAX_CAMPAIGN_GC_MANIFEST_ENTRIES {
            return Err(CampaignGcManifestError::EntryLimit);
        }
        candidates.sort_unstable_by(compare_candidate);
        if candidates
            .windows(2)
            .any(|pair| pair[0].backend == pair[1].backend && pair[0].id == pair[1].id)
        {
            return Err(CampaignGcManifestError::DuplicateCandidate);
        }
        let logical_bytes = candidates.iter().try_fold(0_u64, |total, candidate| {
            total
                .checked_add(candidate.logical_length)
                .ok_or(CampaignGcManifestError::CountOverflow)
        })?;
        Ok(Self {
            candidates: Arc::new(candidates),
            logical_bytes,
            _credit: OptionalMetadataCredit::default(),
        })
    }

    pub(super) fn with_credit(mut self, credit: MetadataCredit) -> Self {
        self._credit = OptionalMetadataCredit::new(credit);
        self
    }

    /// Strictly reads one supported canonical candidate manifest.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcManifestError`] for I/O failure, unsupported magic,
    /// excessive count, malformed fields, noncanonical order, duplicate
    /// placements, accounting overflow, or trailing bytes.
    pub fn from_canonical_reader(
        reader: &mut dyn Read,
        operation: &CampaignGcOperationContext<'_>,
    ) -> Result<Self, CampaignGcManifestError> {
        require_magic(reader, CANDIDATE_MANIFEST_MAGIC)?;
        let count = read_count(reader)?;
        let _codec = operation
            .reserve_bytes((MAX_CONTENT_ID_BYTES + std::mem::size_of::<String>()) as u64)?;
        let bodies = reserve_vector::<CampaignGcCandidate>(operation, count)?;
        let labels = count
            .checked_mul(2 * MAX_CAMPAIGN_GC_BACKEND_ID_BYTES)
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<(MetadataCredit, MetadataCredit)>()
                        + 2 * std::mem::size_of::<usize>(),
                )
            })
            .ok_or(CampaignGcManifestError::CountOverflow)?;
        let labels = MetadataCredit::new(operation.reserve_bytes(labels as u64)?);
        let credit = MetadataCredit::new(crucible_cas::owned_decode::ResourceLoan::new((
            bodies, labels,
        )));
        let mut candidates = allocate_vector(count)?;
        for _ in 0..count {
            let backend = read_bounded_string(reader, MAX_CAMPAIGN_GC_BACKEND_ID_BYTES)?;
            let id = read_content_id(reader)?;
            let logical_length = read_u64(reader)?;
            let candidate = match read_u8(reader)? {
                0 => CampaignGcCandidate::new(backend, id, logical_length)?,
                1 => CampaignGcCandidate::new_reachable_cache(
                    backend,
                    id,
                    logical_length,
                    read_bounded_string(reader, MAX_CAMPAIGN_GC_BACKEND_ID_BYTES)?,
                )?,
                _ => return Err(CampaignGcManifestError::InvalidField),
            };
            candidates.push(candidate);
        }
        require_eof(reader)?;
        if candidates
            .windows(2)
            .any(|pair| compare_candidate(&pair[0], &pair[1]) != Ordering::Less)
        {
            return Err(CampaignGcManifestError::Noncanonical);
        }
        let manifest = Self::new(candidates)?.with_credit(credit);
        Ok(manifest)
    }

    /// Streams this candidate manifest's exact canonical representation.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcManifestError::Io`] if the destination rejects any
    /// bytes. Construction already proves all length fields representable.
    pub fn write_canonical(&self, writer: &mut dyn Write) -> Result<(), CampaignGcManifestError> {
        writer.write_all(CANDIDATE_MANIFEST_MAGIC)?;
        writer.write_all(&entry_count(self.candidates.len())?.to_be_bytes())?;
        for candidate in self.candidates.iter() {
            write_bounded_string(
                writer,
                candidate.backend(),
                MAX_CAMPAIGN_GC_BACKEND_ID_BYTES,
            )?;
            write_content_id(writer, candidate.id())?;
            writer.write_all(&candidate.logical_length().to_be_bytes())?;
            match candidate.reason() {
                CampaignGcCandidateReason::Unreachable => writer.write_all(&[0])?,
                CampaignGcCandidateReason::ReachableCache { required_backend } => {
                    writer.write_all(&[1])?;
                    write_bounded_string(
                        writer,
                        required_backend,
                        MAX_CAMPAIGN_GC_BACKEND_ID_BYTES,
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Returns the exact manifest identity and terminal counters.
    #[must_use]
    pub fn summary(&self) -> CampaignGcCandidateSetSummary {
        let mut hasher = manifest_hasher(CANDIDATE_MANIFEST_HASH_DOMAIN);
        hasher.update(CANDIDATE_MANIFEST_MAGIC);
        hasher.update(&(self.candidates.len() as u64).to_be_bytes());
        for candidate in self.candidates.iter() {
            hash_bounded_string(&mut hasher, candidate.backend());
            hash_content_id(&mut hasher, candidate.id());
            hasher.update(&candidate.logical_length().to_be_bytes());
            match candidate.reason() {
                CampaignGcCandidateReason::Unreachable => {
                    hasher.update(&[0]);
                }
                CampaignGcCandidateReason::ReachableCache { required_backend } => {
                    hasher.update(&[1]);
                    hash_bounded_string(&mut hasher, required_backend);
                }
            }
        }
        let id = CampaignGcCandidateSetId::from_hash(CampaignHash::from_bytes(
            *hasher.finalize().as_bytes(),
        ));
        CampaignGcCandidateSetSummary::new(id, self.candidates.len() as u64, self.logical_bytes)
    }

    /// Returns the number of physical candidates.
    #[must_use]
    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    /// Returns whether the candidate set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// Returns the checked total candidate logical bytes.
    #[must_use]
    pub const fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }

    /// Returns candidates authorized because their logical object is unreachable.
    #[must_use]
    pub fn unreachable_candidates(&self) -> u64 {
        self.candidates
            .iter()
            .filter(|candidate| {
                matches!(candidate.reason(), CampaignGcCandidateReason::Unreachable)
            })
            .count() as u64
    }

    /// Returns reachable cache candidates authorized by current policy.
    #[must_use]
    pub fn reachable_cache_candidates(&self) -> u64 {
        self.candidates
            .iter()
            .filter(|candidate| {
                matches!(
                    candidate.reason(),
                    CampaignGcCandidateReason::ReachableCache { .. }
                )
            })
            .count() as u64
    }

    /// Iterates candidates in canonical physical order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &CampaignGcCandidate> {
        self.candidates.iter()
    }

    pub(super) fn for_backend(&self, backend: &str) -> &[CampaignGcCandidate] {
        let start = self
            .candidates
            .partition_point(|candidate| candidate.backend() < backend);
        let end = self
            .candidates
            .partition_point(|candidate| candidate.backend() <= backend);
        &self.candidates[start..end]
    }
}

/// Failure to construct, encode, or decode a canonical GC manifest.
#[derive(Debug, Error)]
pub enum CampaignGcManifestError {
    /// The original operation refused metadata credit or allocation failed.
    #[error("campaign GC manifest resource admission failed")]
    Resources(#[from] StoreError),
    /// A manifest contains more entries than the fixed work bound.
    #[error("campaign GC manifest entry limit exceeded")]
    EntryLimit,
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
    /// The canonical stream is truncated, unreadable, or unwritable.
    #[error("campaign GC manifest I/O failed")]
    Io(#[from] io::Error),
}

fn manifest_hasher(domain: &[u8]) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher
}

fn compare_candidate(left: &CampaignGcCandidate, right: &CampaignGcCandidate) -> Ordering {
    left.backend
        .cmp(&right.backend)
        .then_with(|| compare_content_id(left.id, right.id))
}

fn compare_content_id(left: ContentId, right: ContentId) -> Ordering {
    left.kind()
        .as_str()
        .cmp(right.kind().as_str())
        .then_with(|| left.schema_version().cmp(&right.schema_version()))
        .then_with(|| left.digest().cmp(&right.digest()))
}

fn hash_bounded_string(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u16).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn entry_count(count: usize) -> Result<u64, CampaignGcManifestError> {
    u64::try_from(count).map_err(|_| CampaignGcManifestError::EntryLimit)
}

fn read_count(reader: &mut dyn Read) -> Result<usize, CampaignGcManifestError> {
    let count = read_u64(reader)?;
    let count = usize::try_from(count).map_err(|_| CampaignGcManifestError::EntryLimit)?;
    if count > MAX_CAMPAIGN_GC_MANIFEST_ENTRIES {
        return Err(CampaignGcManifestError::EntryLimit);
    }
    Ok(count)
}

fn require_magic(reader: &mut dyn Read, expected: &[u8]) -> Result<(), CampaignGcManifestError> {
    let mut actual = [0_u8; 64];
    let actual = actual
        .get_mut(..expected.len())
        .ok_or(CampaignGcManifestError::UnsupportedSchema)?;
    reader.read_exact(actual)?;
    if actual == expected {
        Ok(())
    } else {
        Err(CampaignGcManifestError::UnsupportedSchema)
    }
}

fn read_u16(reader: &mut dyn Read) -> Result<u16, CampaignGcManifestError> {
    let mut bytes = [0_u8; 2];
    reader.read_exact(&mut bytes)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u8(reader: &mut dyn Read) -> Result<u8, CampaignGcManifestError> {
    let mut byte = [0_u8; 1];
    reader.read_exact(&mut byte)?;
    Ok(byte[0])
}

fn read_u64(reader: &mut dyn Read) -> Result<u64, CampaignGcManifestError> {
    let mut bytes = [0_u8; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

fn read_bounded_string(
    reader: &mut dyn Read,
    maximum: usize,
) -> Result<String, CampaignGcManifestError> {
    let length = usize::from(read_u16(reader)?);
    if length == 0 || length > maximum {
        return Err(CampaignGcManifestError::InvalidField);
    }
    let mut bytes = allocate_vector(length)?;
    bytes.resize(length, 0);
    reader.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(|_| CampaignGcManifestError::InvalidField)
}

fn read_content_id(reader: &mut dyn Read) -> Result<ContentId, CampaignGcManifestError> {
    let length = usize::from(read_u16(reader)?);
    if length == 0 || length > MAX_CONTENT_ID_BYTES {
        return Err(CampaignGcManifestError::InvalidField);
    }
    let mut bytes = [0_u8; MAX_CONTENT_ID_BYTES];
    reader.read_exact(&mut bytes[..length])?;
    let encoded =
        std::str::from_utf8(&bytes[..length]).map_err(|_| CampaignGcManifestError::InvalidField)?;
    let id = ContentId::parse(encoded).map_err(|_| CampaignGcManifestError::InvalidField)?;
    Ok(id)
}

fn content_id_bytes(id: ContentId) -> ([u8; MAX_CONTENT_ID_BYTES], usize) {
    let mut bytes = [0_u8; MAX_CONTENT_ID_BYTES];
    let kind = id.kind().as_str().as_bytes();
    bytes[..kind.len()].copy_from_slice(kind);
    let mut length = kind.len();
    bytes[length] = b'.';
    length += 1;
    let mut digits = [0_u8; 10];
    let mut cursor = digits.len();
    let mut version = id.schema_version();
    loop {
        cursor -= 1;
        digits[cursor] = b'0' + (version % 10) as u8;
        version /= 10;
        if version == 0 {
            break;
        }
    }
    let digits = &digits[cursor..];
    bytes[length..length + digits.len()].copy_from_slice(digits);
    length += digits.len();
    bytes[length] = b'.';
    length += 1;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in id.digest() {
        bytes[length] = HEX[(byte >> 4) as usize];
        bytes[length + 1] = HEX[(byte & 15) as usize];
        length += 2;
    }
    (bytes, length)
}

fn write_content_id(writer: &mut dyn Write, id: ContentId) -> Result<(), CampaignGcManifestError> {
    let (bytes, length) = content_id_bytes(id);
    writer.write_all(&(length as u16).to_be_bytes())?;
    writer.write_all(&bytes[..length])?;
    Ok(())
}

fn hash_content_id(hasher: &mut blake3::Hasher, id: ContentId) {
    let (bytes, length) = content_id_bytes(id);
    hasher.update(&(length as u16).to_be_bytes());
    hasher.update(&bytes[..length]);
}

fn write_bounded_string(
    writer: &mut dyn Write,
    value: &str,
    maximum: usize,
) -> Result<(), CampaignGcManifestError> {
    if value.is_empty() || value.len() > maximum {
        return Err(CampaignGcManifestError::InvalidField);
    }
    let length = u16::try_from(value.len()).map_err(|_| CampaignGcManifestError::InvalidField)?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(value.as_bytes())?;
    Ok(())
}

fn require_eof(reader: &mut dyn Read) -> Result<(), CampaignGcManifestError> {
    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing)? == 0 {
        Ok(())
    } else {
        Err(CampaignGcManifestError::Noncanonical)
    }
}
