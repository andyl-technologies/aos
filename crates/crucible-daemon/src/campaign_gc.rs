//! Canonical generation-bound campaign garbage-collection plans.
//!
//! This module owns the small immutable plan header, canonical logical-root and
//! physical-candidate manifests, the non-destructive single-host planner that
//! binds them to every administrative generation, the durable external apply
//! journal, and exact-generation physical-leaf logical deletion under
//! publication/root fences. Policy-aware cache eviction and broader transform
//! administration remain higher-level owner responsibilities.
//!
//! The v1 body is:
//!
//! ```text
//! magic
//! store_graph[32]
//! root_set[32]
//! ref_generation[32] | ref_count:u64be
//! ledger_generation[32] | attempts:u64be | observations:u64be | checkpoints:u64be
//! candidate_set[32] | candidates:u64be | candidate_bytes:u64be
//! physical_count:u16be
//! repeated physical_count times:
//!   backend_length:u16be | backend UTF-8
//!   blob_generation[32] | objects:u64be | logical_bytes:u64be
//! ```

mod apply;
mod journal;
mod manifest;
mod planner;
mod roots;

#[cfg(test)]
use apply::apply_single_host_campaign_gc_with_physical;
pub use apply::{
    CampaignGcApplyError, CampaignGcApplyReport, CampaignGcApplyStatus,
    apply_single_host_campaign_gc,
};
pub use journal::{
    CampaignGcJournalCreateDisposition, CampaignGcJournalError, CampaignGcJournalPhase,
    CampaignGcJournalTransition, DirectoryCampaignGcJournal,
};
pub use manifest::{
    CampaignGcCandidate, CampaignGcCandidateManifest, CampaignGcManifestError,
    CampaignGcRootManifest, MAX_CAMPAIGN_GC_MANIFEST_ENTRIES,
};
#[cfg(test)]
use planner::plan_single_host_campaign_gc_with_physical;
pub use planner::{
    CampaignGcPhysicalStore, CampaignGcPlanningError, CampaignGcPreparedPlan,
    plan_single_host_campaign_gc,
};

use crucible_campaign::CampaignHash;
use crucible_cas::content_store::{
    BlobInventorySummary, InventoryGeneration, RefInventoryGeneration, RefInventorySummary,
};
use thiserror::Error;

use crate::{AssignmentRetentionGeneration, AssignmentRetentionSummary};

const GC_PLAN_MAGIC: &[u8] = b"crucible.campaign.gc-plan.v1\0";
const GC_PLAN_ID_DOMAIN: &str = "crucible.campaign.gc-plan.v1";

/// Maximum canonical byte length of one v1 GC plan header.
pub const MAX_CAMPAIGN_GC_PLAN_BYTES: usize = 64 * 1024;
/// Maximum number of physical blob inventories bound by one plan.
pub const MAX_CAMPAIGN_GC_PHYSICAL_INVENTORIES: usize = 256;
/// Maximum canonical byte length of one physical backend identifier.
pub const MAX_CAMPAIGN_GC_BACKEND_ID_BYTES: usize = 64;

/// Content-derived identity of one canonical GC plan header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CampaignGcPlanId(CampaignHash);

impl CampaignGcPlanId {
    /// Returns the underlying 256-bit campaign hash.
    #[must_use]
    pub const fn as_hash(self) -> CampaignHash {
        self.0
    }

    /// Renders the plan identity as canonical lowercase hexadecimal text.
    #[must_use]
    pub fn to_hex(self) -> String {
        self.0.to_hex()
    }
}

/// Digest of the exact authenticated logical root manifest used for planning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CampaignGcRootSetId(CampaignHash);

impl CampaignGcRootSetId {
    /// Builds a root-set identity from a canonical manifest hash.
    #[must_use]
    pub const fn from_hash(hash: CampaignHash) -> Self {
        Self(hash)
    }

    /// Returns the underlying canonical manifest hash.
    #[must_use]
    pub const fn as_hash(self) -> CampaignHash {
        self.0
    }
}

/// Digest of the exact canonical physical-deletion candidate manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CampaignGcCandidateSetId(CampaignHash);

impl CampaignGcCandidateSetId {
    /// Builds a candidate-set identity from a canonical manifest hash.
    #[must_use]
    pub const fn from_hash(hash: CampaignHash) -> Self {
        Self(hash)
    }

    /// Returns the underlying canonical manifest hash.
    #[must_use]
    pub const fn as_hash(self) -> CampaignHash {
        self.0
    }
}

/// Terminal identity and counters for a canonical candidate manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignGcCandidateSetSummary {
    id: CampaignGcCandidateSetId,
    candidates: u64,
    logical_bytes: u64,
}

impl CampaignGcCandidateSetSummary {
    /// Builds terminal counters for one externally authenticated manifest.
    #[must_use]
    pub const fn new(id: CampaignGcCandidateSetId, candidates: u64, logical_bytes: u64) -> Self {
        Self {
            id,
            candidates,
            logical_bytes,
        }
    }

    /// Returns the canonical candidate-manifest identity.
    #[must_use]
    pub const fn id(self) -> CampaignGcCandidateSetId {
        self.id
    }

    /// Returns the number of physical placements in the manifest.
    #[must_use]
    pub const fn candidates(self) -> u64 {
        self.candidates
    }

    /// Returns the checked sum of candidate logical byte lengths.
    #[must_use]
    pub const fn logical_bytes(self) -> u64 {
        self.logical_bytes
    }
}

/// One physical logical-object inventory basis bound into a GC plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignGcBlobInventoryBasis {
    backend: String,
    generation: InventoryGeneration,
    objects: u64,
    logical_bytes: u64,
}

impl CampaignGcBlobInventoryBasis {
    /// Builds one validated physical inventory basis.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcPlanError::InvalidBackendId`] when `backend` is not
    /// a bounded canonical operational identifier, or
    /// [`CampaignGcPlanError::InvalidPhysicalInventoryCount`] when a zero-object
    /// summary reports nonzero bytes.
    pub fn new(
        backend: impl Into<String>,
        generation: InventoryGeneration,
        objects: u64,
        logical_bytes: u64,
    ) -> Result<Self, CampaignGcPlanError> {
        let backend = backend.into();
        validate_backend_id(&backend)?;
        if objects == 0 && logical_bytes != 0 {
            return Err(CampaignGcPlanError::InvalidPhysicalInventoryCount);
        }
        Ok(Self {
            backend,
            generation,
            objects,
            logical_bytes,
        })
    }

    /// Converts a completed physical inventory summary into a plan basis.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcPlanError::InvalidBackendId`] when the inventory's
    /// backend name is not a canonical plan identifier, or
    /// [`CampaignGcPlanError::InvalidPhysicalInventoryCount`] when its terminal
    /// counters are inconsistent.
    pub fn from_summary(summary: &BlobInventorySummary) -> Result<Self, CampaignGcPlanError> {
        Self::new(
            summary.backend(),
            summary.generation(),
            summary.objects(),
            summary.logical_bytes(),
        )
    }

    /// Returns the exact physical backend identifier.
    #[must_use]
    pub fn backend(&self) -> &str {
        &self.backend
    }

    /// Returns the fenced physical inventory generation.
    #[must_use]
    pub const fn generation(&self) -> InventoryGeneration {
        self.generation
    }

    /// Returns the number of physical objects visited.
    #[must_use]
    pub const fn objects(&self) -> u64 {
        self.objects
    }

    /// Returns the checked sum of physical logical byte lengths.
    #[must_use]
    pub const fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }
}

/// Small canonical header for one generation-bound physical GC plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignGcPlan {
    store_graph: CampaignHash,
    root_set: CampaignGcRootSetId,
    ref_generation: RefInventoryGeneration,
    refs: u64,
    ledger_generation: AssignmentRetentionGeneration,
    attempt_records: u64,
    observation_roots: u64,
    checkpoint_roots: u64,
    candidates: CampaignGcCandidateSetSummary,
    physical: Vec<CampaignGcBlobInventoryBasis>,
}

impl CampaignGcPlan {
    /// Builds a canonical plan from completed administrative inventories.
    ///
    /// `physical` must be strictly ordered by backend identifier. The root and
    /// candidate IDs name separate immutable manifests; this bounded header
    /// never materializes either potentially large set.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcPlanError`] when a backend identifier/order, a
    /// terminal count relationship, or the encoded header bound is invalid.
    pub fn new(
        store_graph: CampaignHash,
        root_set: CampaignGcRootSetId,
        refs: RefInventorySummary,
        ledger: AssignmentRetentionSummary,
        candidates: CampaignGcCandidateSetSummary,
        physical: Vec<CampaignGcBlobInventoryBasis>,
    ) -> Result<Self, CampaignGcPlanError> {
        validate_physical(&physical)?;
        let root_count = ledger
            .observation_roots()
            .checked_add(ledger.checkpoint_roots())
            .ok_or(CampaignGcPlanError::CountOverflow)?;
        if root_count > ledger.attempt_records() {
            return Err(CampaignGcPlanError::InvalidLedgerSummary);
        }
        let (physical_objects, physical_bytes) =
            physical
                .iter()
                .try_fold((0_u64, 0_u64), |(objects, bytes), basis| {
                    Ok::<_, CampaignGcPlanError>((
                        objects
                            .checked_add(basis.objects())
                            .ok_or(CampaignGcPlanError::CountOverflow)?,
                        bytes
                            .checked_add(basis.logical_bytes())
                            .ok_or(CampaignGcPlanError::CountOverflow)?,
                    ))
                })?;
        if candidates.candidates() > physical_objects
            || candidates.logical_bytes() > physical_bytes
            || (candidates.candidates() == 0 && candidates.logical_bytes() != 0)
        {
            return Err(CampaignGcPlanError::InvalidCandidateSummary);
        }

        let plan = Self {
            store_graph,
            root_set,
            ref_generation: refs.generation(),
            refs: refs.refs(),
            ledger_generation: ledger.generation(),
            attempt_records: ledger.attempt_records(),
            observation_roots: ledger.observation_roots(),
            checkpoint_roots: ledger.checkpoint_roots(),
            candidates,
            physical,
        };
        if plan.canonical_bytes_unchecked()?.len() > MAX_CAMPAIGN_GC_PLAN_BYTES {
            return Err(CampaignGcPlanError::PlanTooLarge);
        }
        Ok(plan)
    }

    /// Strictly decodes one canonical v1 plan header.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcPlanError`] for an oversized, truncated,
    /// noncanonical, unsupported, or internally inconsistent header.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignGcPlanError> {
        if bytes.len() > MAX_CAMPAIGN_GC_PLAN_BYTES {
            return Err(CampaignGcPlanError::PlanTooLarge);
        }
        let mut cursor = PlanCursor::new(bytes);
        cursor.require(GC_PLAN_MAGIC)?;
        let store_graph = CampaignHash::from_bytes(cursor.fixed()?);
        let root_set = CampaignGcRootSetId::from_hash(CampaignHash::from_bytes(cursor.fixed()?));
        let ref_generation = RefInventoryGeneration::from_bytes(cursor.fixed()?);
        let refs = cursor.u64()?;
        let ledger_generation = AssignmentRetentionGeneration::from_bytes(cursor.fixed()?);
        let attempt_records = cursor.u64()?;
        let observation_roots = cursor.u64()?;
        let checkpoint_roots = cursor.u64()?;
        let candidate_id =
            CampaignGcCandidateSetId::from_hash(CampaignHash::from_bytes(cursor.fixed()?));
        let candidate_count = cursor.u64()?;
        let candidate_bytes = cursor.u64()?;
        let physical_count = usize::from(cursor.u16()?);
        if physical_count == 0 || physical_count > MAX_CAMPAIGN_GC_PHYSICAL_INVENTORIES {
            return Err(CampaignGcPlanError::InvalidPhysicalInventoryCount);
        }
        let mut physical = Vec::with_capacity(physical_count);
        for _ in 0..physical_count {
            let backend_length = usize::from(cursor.u16()?);
            let backend = std::str::from_utf8(cursor.take(backend_length)?)
                .map_err(|_| CampaignGcPlanError::InvalidBackendId)?
                .to_owned();
            physical.push(CampaignGcBlobInventoryBasis::new(
                backend,
                InventoryGeneration::from_bytes(cursor.fixed()?),
                cursor.u64()?,
                cursor.u64()?,
            )?);
        }
        cursor.finish()?;

        let plan = Self::new(
            store_graph,
            root_set,
            RefInventorySummary::from_parts(ref_generation, refs),
            AssignmentRetentionSummary::new(
                ledger_generation,
                attempt_records,
                observation_roots,
                checkpoint_roots,
            ),
            CampaignGcCandidateSetSummary::new(candidate_id, candidate_count, candidate_bytes),
            physical,
        )?;
        if plan.canonical_bytes()? != bytes {
            return Err(CampaignGcPlanError::Noncanonical);
        }
        Ok(plan)
    }

    /// Encodes the exact canonical v1 plan header.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcPlanError::PlanTooLarge`] if an internal length
    /// cannot be represented within the frozen v1 bounds.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CampaignGcPlanError> {
        self.canonical_bytes_unchecked()
    }

    /// Returns the content-derived canonical plan identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcPlanError::PlanTooLarge`] if encoding unexpectedly
    /// exceeds the frozen v1 bounds.
    pub fn id(&self) -> Result<CampaignGcPlanId, CampaignGcPlanError> {
        Ok(CampaignGcPlanId(CampaignHash::derive(
            GC_PLAN_ID_DOMAIN,
            &self.canonical_bytes()?,
        )))
    }

    /// Returns the exact admitted store-graph configuration hash.
    #[must_use]
    pub const fn store_graph(&self) -> CampaignHash {
        self.store_graph
    }

    /// Returns the logical root-manifest identity.
    #[must_use]
    pub const fn root_set(&self) -> CampaignGcRootSetId {
        self.root_set
    }

    /// Returns the authoritative ref-namespace generation.
    #[must_use]
    pub const fn ref_generation(&self) -> RefInventoryGeneration {
        self.ref_generation
    }

    /// Returns the number of authoritative refs in the fenced namespace.
    #[must_use]
    pub const fn refs(&self) -> u64 {
        self.refs
    }

    /// Returns the operational assignment-ledger generation.
    #[must_use]
    pub const fn ledger_generation(&self) -> AssignmentRetentionGeneration {
        self.ledger_generation
    }

    /// Returns the number of authenticated operational attempt records.
    #[must_use]
    pub const fn attempt_records(&self) -> u64 {
        self.attempt_records
    }

    /// Returns the number of observation roots in the ledger inventory.
    #[must_use]
    pub const fn observation_roots(&self) -> u64 {
        self.observation_roots
    }

    /// Returns the number of exact-checkpoint roots in the ledger inventory.
    #[must_use]
    pub const fn checkpoint_roots(&self) -> u64 {
        self.checkpoint_roots
    }

    /// Returns the candidate-manifest terminal summary.
    #[must_use]
    pub const fn candidates(&self) -> CampaignGcCandidateSetSummary {
        self.candidates
    }

    /// Returns the ordered physical inventory bases.
    #[must_use]
    pub fn physical(&self) -> &[CampaignGcBlobInventoryBasis] {
        &self.physical
    }

    fn canonical_bytes_unchecked(&self) -> Result<Vec<u8>, CampaignGcPlanError> {
        let mut bytes = Vec::with_capacity(MAX_CAMPAIGN_GC_PLAN_BYTES.min(1024));
        bytes.extend_from_slice(GC_PLAN_MAGIC);
        bytes.extend_from_slice(&self.store_graph.as_bytes());
        bytes.extend_from_slice(&self.root_set.as_hash().as_bytes());
        bytes.extend_from_slice(&self.ref_generation.as_bytes());
        bytes.extend_from_slice(&self.refs.to_be_bytes());
        bytes.extend_from_slice(&self.ledger_generation.as_bytes());
        bytes.extend_from_slice(&self.attempt_records.to_be_bytes());
        bytes.extend_from_slice(&self.observation_roots.to_be_bytes());
        bytes.extend_from_slice(&self.checkpoint_roots.to_be_bytes());
        bytes.extend_from_slice(&self.candidates.id().as_hash().as_bytes());
        bytes.extend_from_slice(&self.candidates.candidates().to_be_bytes());
        bytes.extend_from_slice(&self.candidates.logical_bytes().to_be_bytes());
        let physical_count =
            u16::try_from(self.physical.len()).map_err(|_| CampaignGcPlanError::PlanTooLarge)?;
        bytes.extend_from_slice(&physical_count.to_be_bytes());
        for basis in &self.physical {
            let backend_length = u16::try_from(basis.backend().len())
                .map_err(|_| CampaignGcPlanError::PlanTooLarge)?;
            bytes.extend_from_slice(&backend_length.to_be_bytes());
            bytes.extend_from_slice(basis.backend().as_bytes());
            bytes.extend_from_slice(&basis.generation().as_bytes());
            bytes.extend_from_slice(&basis.objects().to_be_bytes());
            bytes.extend_from_slice(&basis.logical_bytes().to_be_bytes());
        }
        if bytes.len() > MAX_CAMPAIGN_GC_PLAN_BYTES {
            return Err(CampaignGcPlanError::PlanTooLarge);
        }
        Ok(bytes)
    }
}

/// Failure to construct or decode one canonical generation-bound GC plan.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CampaignGcPlanError {
    /// A backend identifier violates the frozen v1 grammar or bound.
    #[error("campaign GC plan backend identifier is invalid")]
    InvalidBackendId,
    /// Physical inventories are absent, excessive, duplicated, or unordered.
    #[error("campaign GC plan physical inventory list is invalid")]
    InvalidPhysicalInventoryCount,
    /// Operational root counters are inconsistent with visited attempt records.
    #[error("campaign GC plan ledger summary is inconsistent")]
    InvalidLedgerSummary,
    /// Candidate counters exceed the complete physical inventory.
    #[error("campaign GC plan candidate summary exceeds physical inventory")]
    InvalidCandidateSummary,
    /// A checked terminal counter overflowed.
    #[error("campaign GC plan terminal count overflow")]
    CountOverflow,
    /// The canonical plan header exceeds its frozen v1 byte bound.
    #[error("campaign GC plan exceeds its canonical byte bound")]
    PlanTooLarge,
    /// The header is truncated or has trailing bytes.
    #[error("campaign GC plan is truncated or has trailing bytes")]
    InvalidLength,
    /// The header magic or version is unsupported.
    #[error("campaign GC plan schema is unsupported")]
    UnsupportedSchema,
    /// The supplied bytes have an alternative noncanonical representation.
    #[error("campaign GC plan encoding is noncanonical")]
    Noncanonical,
}

fn validate_backend_id(value: &str) -> Result<(), CampaignGcPlanError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_CAMPAIGN_GC_BACKEND_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(CampaignGcPlanError::InvalidBackendId)
    }
}

fn validate_physical(physical: &[CampaignGcBlobInventoryBasis]) -> Result<(), CampaignGcPlanError> {
    if physical.is_empty() || physical.len() > MAX_CAMPAIGN_GC_PHYSICAL_INVENTORIES {
        return Err(CampaignGcPlanError::InvalidPhysicalInventoryCount);
    }
    let ordered = physical
        .windows(2)
        .all(|pair| pair[0].backend() < pair[1].backend());
    if ordered {
        Ok(())
    } else {
        Err(CampaignGcPlanError::InvalidPhysicalInventoryCount)
    }
}

struct PlanCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> PlanCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CampaignGcPlanError> {
        if self.remaining.len() < length {
            return Err(CampaignGcPlanError::InvalidLength);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], CampaignGcPlanError> {
        self.take(N)?
            .try_into()
            .map_err(|_| CampaignGcPlanError::InvalidLength)
    }

    fn u16(&mut self) -> Result<u16, CampaignGcPlanError> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }

    fn u64(&mut self) -> Result<u64, CampaignGcPlanError> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    fn require(&mut self, expected: &[u8]) -> Result<(), CampaignGcPlanError> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(CampaignGcPlanError::UnsupportedSchema)
        }
    }

    fn finish(self) -> Result<(), CampaignGcPlanError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(CampaignGcPlanError::InvalidLength)
        }
    }
}

#[cfg(test)]
mod tests;
