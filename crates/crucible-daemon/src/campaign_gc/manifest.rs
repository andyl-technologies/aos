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

/// One exact physical loose-object placement approved for deletion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignGcCandidate {
    backend: String,
    id: ContentId,
    logical_length: u64,
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

    pub(super) fn compare_id(&self, id: ContentId) -> Ordering {
        compare_content_id(self.id, id)
    }
}

/// Canonical ordered physical-deletion candidate manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignGcCandidateManifest {
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
    /// if logical byte accounting overflows.
    pub fn new(mut candidates: Vec<CampaignGcCandidate>) -> Result<Self, CampaignGcManifestError> {
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
            candidates,
            logical_bytes,
        })
    }

    /// Strictly reads one canonical v1 candidate manifest.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcManifestError`] for I/O failure, unsupported magic,
    /// excessive count, malformed fields, noncanonical order, duplicate
    /// placements, accounting overflow, or trailing bytes.
    pub fn from_canonical_reader(reader: &mut dyn Read) -> Result<Self, CampaignGcManifestError> {
        require_magic(reader, CANDIDATE_MANIFEST_MAGIC)?;
        let count = read_count(reader)?;
        let mut candidates = Vec::with_capacity(count.min(4_096));
        for _ in 0..count {
            let backend = read_bounded_string(reader, MAX_CAMPAIGN_GC_BACKEND_ID_BYTES)?;
            let id = read_content_id(reader)?;
            let logical_length = read_u64(reader)?;
            candidates.push(CampaignGcCandidate::new(backend, id, logical_length)?);
        }
        require_eof(reader)?;
        if candidates
            .windows(2)
            .any(|pair| compare_candidate(&pair[0], &pair[1]) != Ordering::Less)
        {
            return Err(CampaignGcManifestError::Noncanonical);
        }
        let manifest = Self::new(candidates)?;
        Ok(manifest)
    }

    /// Streams the exact canonical v1 representation.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcManifestError::Io`] if the destination rejects any
    /// bytes. Construction already proves all length fields representable.
    pub fn write_canonical(&self, writer: &mut dyn Write) -> Result<(), CampaignGcManifestError> {
        writer.write_all(CANDIDATE_MANIFEST_MAGIC)?;
        writer.write_all(&entry_count(self.candidates.len())?.to_be_bytes())?;
        for candidate in &self.candidates {
            write_bounded_string(
                writer,
                candidate.backend(),
                MAX_CAMPAIGN_GC_BACKEND_ID_BYTES,
            )?;
            write_bounded_string(writer, &candidate.id().encode(), MAX_CONTENT_ID_BYTES)?;
            writer.write_all(&candidate.logical_length().to_be_bytes())?;
        }
        Ok(())
    }

    /// Returns the exact manifest identity and terminal counters.
    #[must_use]
    pub fn summary(&self) -> CampaignGcCandidateSetSummary {
        let mut hasher = manifest_hasher(CANDIDATE_MANIFEST_HASH_DOMAIN);
        hasher.update(CANDIDATE_MANIFEST_MAGIC);
        hasher.update(&(self.candidates.len() as u64).to_be_bytes());
        for candidate in &self.candidates {
            hash_bounded_string(&mut hasher, candidate.backend());
            hash_bounded_string(&mut hasher, &candidate.id().encode());
            hasher.update(&candidate.logical_length().to_be_bytes());
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
