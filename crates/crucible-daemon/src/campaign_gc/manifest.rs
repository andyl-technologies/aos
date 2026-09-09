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
//! The v1 candidate format is:
//!
//! ```text
//! "crucible.campaign.gc-candidate-manifest.v1\0"
//! candidate_count:u64be
//! repeated candidate_count times in strict
//! (backend, kind tag, schema version, digest) order:
//!   backend_length:u16be || backend_utf8
//!   content_id_length:u16be || content_id_utf8
//!   logical_length:u64be
//! ```
//!
//! Version 2 appends an explicit reason to every entry:
//!
//! ```text
//! reason:u8 # 0 unreachable, 1 reachable read-through cache
//! if reason == 1:
//!   required_backend_length:u16be || required_backend_utf8
//! ```

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::io::{self, Read, Write};

use crucible_campaign::{CampaignHash, MAX_CAMPAIGN_CLOSURE_OBJECTS};
use crucible_cas::content_store::ContentId;
use thiserror::Error;

use super::{
    CampaignGcCandidateSetId, CampaignGcCandidateSetSummary, CampaignGcRootSetId,
    MAX_CAMPAIGN_GC_BACKEND_ID_BYTES, validate_backend_id,
};

const ROOT_MANIFEST_MAGIC: &[u8] = b"crucible.campaign.gc-root-manifest.v1\0";
const ROOT_MANIFEST_HASH_DOMAIN: &[u8] = b"crucible.campaign.gc-root-manifest.v1";
const CANDIDATE_MANIFEST_MAGIC: &[u8] = b"crucible.campaign.gc-candidate-manifest.v1\0";
const CANDIDATE_MANIFEST_HASH_DOMAIN: &[u8] = b"crucible.campaign.gc-candidate-manifest.v1";
const CANDIDATE_MANIFEST_V2_MAGIC: &[u8] = b"crucible.campaign.gc-candidate-manifest.v2\0";
const CANDIDATE_MANIFEST_V2_HASH_DOMAIN: &[u8] = b"crucible.campaign.gc-candidate-manifest.v2";
const MAX_CONTENT_ID_BYTES: usize = 128;

/// Maximum number of roots or physical placements in one local v1 manifest.
///
/// This matches the repository's complete-closure work bound. Implementations
/// reject before retaining an additional entry once this bound is reached.
pub const MAX_CAMPAIGN_GC_MANIFEST_ENTRIES: usize = MAX_CAMPAIGN_CLOSURE_OBJECTS;

/// Exact sorted set of logical roots used for reachability planning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignGcRootManifest {
    roots: Vec<ContentId>,
}

impl CampaignGcRootManifest {
    /// Builds a deduplicated canonical root manifest.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcManifestError::EntryLimit`] if more than the fixed
    /// v1 root bound is supplied.
    pub fn new(
        roots: impl IntoIterator<Item = ContentId>,
    ) -> Result<Self, CampaignGcManifestError> {
        let mut canonical = BTreeSet::new();
        let mut observed = 0_usize;
        for root in roots {
            observed = observed
                .checked_add(1)
                .ok_or(CampaignGcManifestError::EntryLimit)?;
            if observed > MAX_CAMPAIGN_GC_MANIFEST_ENTRIES {
                return Err(CampaignGcManifestError::EntryLimit);
            }
            canonical.insert(root);
        }
        let mut roots = canonical.into_iter().collect::<Vec<_>>();
        roots.sort_unstable_by(|left, right| compare_content_id(*left, *right));
        Ok(Self { roots })
    }

    /// Strictly reads one canonical v1 root manifest.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcManifestError`] for I/O failure, unsupported magic,
    /// excessive count, malformed IDs, noncanonical order, or trailing bytes.
    pub fn from_canonical_reader(reader: &mut dyn Read) -> Result<Self, CampaignGcManifestError> {
        require_magic(reader, ROOT_MANIFEST_MAGIC)?;
        let count = read_count(reader)?;
        let mut roots = Vec::with_capacity(count.min(4_096));
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
        Ok(Self { roots })
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
        for root in &self.roots {
            write_bounded_string(writer, &root.encode(), MAX_CONTENT_ID_BYTES)?;
        }
        Ok(())
    }

    /// Returns the exact manifest identity.
    #[must_use]
    pub fn id(&self) -> CampaignGcRootSetId {
        let mut hasher = manifest_hasher(ROOT_MANIFEST_HASH_DOMAIN);
        hasher.update(ROOT_MANIFEST_MAGIC);
        hasher.update(&(self.roots.len() as u64).to_be_bytes());
        for root in &self.roots {
            hash_bounded_string(&mut hasher, &root.encode());
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
    /// A reachable copy is a read-through cache backed by a required copy.
    ReachableReadThroughCache {
        /// Physical backend whose v2 plan basis authenticates the required copy.
        required_backend: String,
    },
}

/// Canonical candidate-manifest schema version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignGcCandidateManifestVersion {
    /// Frozen unreachable-only manifest.
    V1,
    /// Policy-aware manifest with explicit deletion reasons.
    V2,
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

    /// Builds one reachable read-through cache candidate and required-copy basis.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcManifestError::InvalidBackendId`] if either backend
    /// violates the operational identifier grammar, or
    /// [`CampaignGcManifestError::InvalidField`] if both names are equal.
    pub fn new_reachable_read_through_cache(
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
            reason: CampaignGcCandidateReason::ReachableReadThroughCache { required_backend },
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
    version: CampaignGcCandidateManifestVersion,
    candidates: Vec<CampaignGcCandidate>,
    logical_bytes: u64,
}

impl CampaignGcCandidateManifest {
    /// Builds and canonically orders one candidate manifest.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcManifestError::EntryLimit`] for an excessive entry
    /// count, [`CampaignGcManifestError::DuplicateCandidate`] for the same
    /// physical placement twice, or [`CampaignGcManifestError::CountOverflow`]
    /// if logical byte accounting overflows. Returns
    /// [`CampaignGcManifestError::InvalidField`] if any candidate has a
    /// reachable policy reason, which requires [`Self::new_policy_aware`].
    pub fn new(candidates: Vec<CampaignGcCandidate>) -> Result<Self, CampaignGcManifestError> {
        if candidates
            .iter()
            .any(|candidate| !matches!(candidate.reason(), CampaignGcCandidateReason::Unreachable))
        {
            return Err(CampaignGcManifestError::InvalidField);
        }
        Self::new_with_version(CampaignGcCandidateManifestVersion::V1, candidates)
    }

    /// Builds a canonical policy-aware v2 candidate manifest.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcManifestError`] for the same bounds, duplicate, and
    /// accounting failures as [`Self::new`].
    pub fn new_policy_aware(
        candidates: Vec<CampaignGcCandidate>,
    ) -> Result<Self, CampaignGcManifestError> {
        Self::new_with_version(CampaignGcCandidateManifestVersion::V2, candidates)
    }

    fn new_with_version(
        version: CampaignGcCandidateManifestVersion,
        mut candidates: Vec<CampaignGcCandidate>,
    ) -> Result<Self, CampaignGcManifestError> {
        if candidates.len() > MAX_CAMPAIGN_GC_MANIFEST_ENTRIES {
            return Err(CampaignGcManifestError::EntryLimit);
        }
        candidates.sort_by(compare_candidate);
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
            version,
            candidates,
            logical_bytes,
        })
    }

    /// Strictly reads one supported canonical candidate manifest.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcManifestError`] for I/O failure, unsupported magic,
    /// excessive count, malformed fields, noncanonical order, duplicate
    /// placements, accounting overflow, or trailing bytes.
    pub fn from_canonical_reader(reader: &mut dyn Read) -> Result<Self, CampaignGcManifestError> {
        let version = read_candidate_manifest_version(reader)?;
        let count = read_count(reader)?;
        let mut candidates = Vec::with_capacity(count.min(4_096));
        for _ in 0..count {
            let backend = read_bounded_string(reader, MAX_CAMPAIGN_GC_BACKEND_ID_BYTES)?;
            let id = read_content_id(reader)?;
            let logical_length = read_u64(reader)?;
            let candidate = match version {
                CampaignGcCandidateManifestVersion::V1 => {
                    CampaignGcCandidate::new(backend, id, logical_length)?
                }
                CampaignGcCandidateManifestVersion::V2 => match read_u8(reader)? {
                    0 => CampaignGcCandidate::new(backend, id, logical_length)?,
                    1 => CampaignGcCandidate::new_reachable_read_through_cache(
                        backend,
                        id,
                        logical_length,
                        read_bounded_string(reader, MAX_CAMPAIGN_GC_BACKEND_ID_BYTES)?,
                    )?,
                    _ => return Err(CampaignGcManifestError::InvalidField),
                },
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
        let manifest = Self::new_with_version(version, candidates)?;
        Ok(manifest)
    }

    /// Streams this candidate manifest's exact canonical representation.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcManifestError::Io`] if the destination rejects any
    /// bytes. Construction already proves all length fields representable.
    pub fn write_canonical(&self, writer: &mut dyn Write) -> Result<(), CampaignGcManifestError> {
        writer.write_all(self.magic())?;
        writer.write_all(&entry_count(self.candidates.len())?.to_be_bytes())?;
        for candidate in &self.candidates {
            write_bounded_string(
                writer,
                candidate.backend(),
                MAX_CAMPAIGN_GC_BACKEND_ID_BYTES,
            )?;
            write_bounded_string(writer, &candidate.id().encode(), MAX_CONTENT_ID_BYTES)?;
            writer.write_all(&candidate.logical_length().to_be_bytes())?;
            if self.version == CampaignGcCandidateManifestVersion::V2 {
                match candidate.reason() {
                    CampaignGcCandidateReason::Unreachable => writer.write_all(&[0])?,
                    CampaignGcCandidateReason::ReachableReadThroughCache { required_backend } => {
                        writer.write_all(&[1])?;
                        write_bounded_string(
                            writer,
                            required_backend,
                            MAX_CAMPAIGN_GC_BACKEND_ID_BYTES,
                        )?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Returns the exact manifest identity and terminal counters.
    #[must_use]
    pub fn summary(&self) -> CampaignGcCandidateSetSummary {
        let mut hasher = manifest_hasher(self.hash_domain());
        hasher.update(self.magic());
        hasher.update(&(self.candidates.len() as u64).to_be_bytes());
        for candidate in &self.candidates {
            hash_bounded_string(&mut hasher, candidate.backend());
            hash_bounded_string(&mut hasher, &candidate.id().encode());
            hasher.update(&candidate.logical_length().to_be_bytes());
            if self.version == CampaignGcCandidateManifestVersion::V2 {
                match candidate.reason() {
                    CampaignGcCandidateReason::Unreachable => {
                        hasher.update(&[0]);
                    }
                    CampaignGcCandidateReason::ReachableReadThroughCache { required_backend } => {
                        hasher.update(&[1]);
                        hash_bounded_string(&mut hasher, required_backend);
                    }
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

    /// Returns reachable read-through cache candidates authorized by v2 policy.
    #[must_use]
    pub fn reachable_cache_candidates(&self) -> u64 {
        self.candidates
            .iter()
            .filter(|candidate| {
                matches!(
                    candidate.reason(),
                    CampaignGcCandidateReason::ReachableReadThroughCache { .. }
                )
            })
            .count() as u64
    }

    /// Returns the exact canonical manifest schema.
    #[must_use]
    pub const fn version(&self) -> CampaignGcCandidateManifestVersion {
        self.version
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

    fn magic(&self) -> &'static [u8] {
        match self.version {
            CampaignGcCandidateManifestVersion::V1 => CANDIDATE_MANIFEST_MAGIC,
            CampaignGcCandidateManifestVersion::V2 => CANDIDATE_MANIFEST_V2_MAGIC,
        }
    }

    fn hash_domain(&self) -> &'static [u8] {
        match self.version {
            CampaignGcCandidateManifestVersion::V1 => CANDIDATE_MANIFEST_HASH_DOMAIN,
            CampaignGcCandidateManifestVersion::V2 => CANDIDATE_MANIFEST_V2_HASH_DOMAIN,
        }
    }
}

/// Failure to construct, encode, or decode a canonical GC manifest.
#[derive(Debug, Error)]
pub enum CampaignGcManifestError {
    /// A manifest contains more entries than the fixed v1 work bound.
    #[error("campaign GC manifest entry limit exceeded")]
    EntryLimit,
    /// A physical backend identifier violates the v1 grammar.
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
    let mut actual = vec![0_u8; expected.len()];
    reader.read_exact(&mut actual)?;
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

fn read_candidate_manifest_version(
    reader: &mut dyn Read,
) -> Result<CampaignGcCandidateManifestVersion, CampaignGcManifestError> {
    let mut magic = vec![0_u8; CANDIDATE_MANIFEST_MAGIC.len()];
    reader.read_exact(&mut magic)?;
    if magic == CANDIDATE_MANIFEST_MAGIC {
        Ok(CampaignGcCandidateManifestVersion::V1)
    } else if magic == CANDIDATE_MANIFEST_V2_MAGIC {
        Ok(CampaignGcCandidateManifestVersion::V2)
    } else {
        Err(CampaignGcManifestError::UnsupportedSchema)
    }
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
    let mut bytes = vec![0_u8; length];
    reader.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(|_| CampaignGcManifestError::InvalidField)
}

fn read_content_id(reader: &mut dyn Read) -> Result<ContentId, CampaignGcManifestError> {
    let encoded = read_bounded_string(reader, MAX_CONTENT_ID_BYTES)?;
    ContentId::parse(&encoded).map_err(|_| CampaignGcManifestError::InvalidField)
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
