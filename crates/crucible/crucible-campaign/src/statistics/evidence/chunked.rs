//! Chunked portable statistical evidence: one manifest plus ordered chunks.
//!
//! A finished statistical campaign can hold far more evidence than one
//! transport message. The portable form therefore splits it into a manifest
//! that binds the snapshot, planning view, policy, lineage, and ordered chunk
//! digests, and chunks that each carry a contiguous run of evidence items.
//! Items are numbered in replay order: every stage-zero draw in coordinate
//! order, then every SMC transition in stage and slot order. Each chunk is at
//! most [`MAX_STATISTICAL_EVIDENCE_BYTES`] and [`MAX_STATISTICAL_EVIDENCE_ITEMS`],
//! so a service can return one chunk per response and a verifier can check
//! chunks in order while retaining only the bounded replay state.
//!
//! ```text
//! manifest v2:
//!   u32 schema-version = 2
//!   CampaignSnapshot snapshot
//!   CampaignPlanningView planning-view
//!   CampaignPolicy policy
//!   CampaignLineage lineage
//!   u64 item-count
//!   sequence (u32 index, u64 first-item, u32 item-count, hash32 digest) chunks
//!
//! chunk v1:
//!   u32 schema-version = 1
//!   u32 index
//!   u64 first-item
//!   sequence (u8 tag, draw | transition) items
//!
//! digest = H("crucible.campaign.statistical-evidence-chunk.v1", chunk bytes)
//! ```
//!
//! The unversioned single-blob bundle that preceded this form is no longer
//! accepted.

use super::*;
use crate::{SequentialMonteCarloEstimateReport, StatisticalEstimateReport};

/// Current manifest schema; the retired unversioned single-blob bundle counts as version one.
const STATISTICAL_EVIDENCE_MANIFEST_SCHEMA_VERSION: u32 = 2;

/// Current chunk schema.
const STATISTICAL_EVIDENCE_CHUNK_SCHEMA_VERSION: u32 = 1;

/// Hash domain naming one canonical chunk body.
const STATISTICAL_EVIDENCE_CHUNK_DIGEST_DOMAIN: &str =
    "crucible.campaign.statistical-evidence-chunk.v1";

/// Maximum chunks named by one statistical evidence manifest.
pub const MAX_STATISTICAL_EVIDENCE_CHUNKS: usize = 262_144;

/// One stage-zero draw or one SMC transition in replay order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatisticalEvidenceItem {
    /// A finite stage-zero draw.
    Draw(StatisticalDrawEvidence),
    /// A post-initial SMC transition.
    Transition(SmcTransitionEvidence),
}

impl StatisticalEvidenceItem {
    /// Derives the snapshot-root memberships required by this item.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when an object identity cannot be formed
    /// or two bodies claim different values for one root key.
    pub fn required_root_lookups(&self) -> Result<Vec<StatisticalRootLookup>, CampaignCodecError> {
        let mut lookups = BTreeMap::new();
        self.collect_lookups(&mut lookups)?;
        finish_lookups(lookups)
    }

    fn collect_lookups(&self, lookups: &mut LookupMap) -> Result<(), CampaignCodecError> {
        match self {
            Self::Draw(draw) => collect_execution_lookups(
                lookups,
                statistical_draw_request_key(draw.coordinate()),
                statistical_draw_proposal_key(draw.coordinate()),
                draw.execution(),
            ),
            Self::Transition(transition) => collect_execution_lookups(
                lookups,
                smc_transition_request_key(transition.stage(), transition.slot()),
                smc_transition_proposal_key(transition.stage(), transition.slot()),
                transition.execution(),
            ),
        }
    }
}

impl Canonical for StatisticalEvidenceItem {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Draw(draw) => {
                encoder.u8(0);
                draw.encode(encoder);
            }
            Self::Transition(transition) => {
                encoder.u8(1);
                transition.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => StatisticalDrawEvidence::decode(decoder).map(Self::Draw),
            1 => SmcTransitionEvidence::decode(decoder).map(Self::Transition),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "statistical-evidence-item",
                tag,
            }),
        }
    }
}

/// One contiguous, size-bounded run of evidence items.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatisticalEvidenceChunk {
    index: u32,
    first_item: u64,
    items: Vec<StatisticalEvidenceItem>,
}

impl StatisticalEvidenceChunk {
    /// Builds a chunk after enforcing its item and byte bounds.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an empty or oversized chunk.
    pub fn new(
        index: u32,
        first_item: u64,
        items: Vec<StatisticalEvidenceItem>,
    ) -> Result<Self, CampaignCodecError> {
        if items.is_empty() || items.len() > MAX_STATISTICAL_EVIDENCE_ITEMS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "statistical-evidence-chunk-items",
            });
        }
        let chunk = Self {
            index,
            first_item,
            items,
        };
        crate::codec::ensure_encoded_size(
            &chunk,
            MAX_STATISTICAL_EVIDENCE_BYTES,
            "statistical-evidence-chunk-bytes",
        )?;
        Ok(chunk)
    }

    /// Returns the chunk's zero-based position in its manifest.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// Returns the replay-order number of the chunk's first item.
    #[must_use]
    pub const fn first_item(&self) -> u64 {
        self.first_item
    }

    /// Returns the chunk's items in replay order.
    #[must_use]
    pub fn items(&self) -> &[StatisticalEvidenceItem] {
        &self.items
    }

    /// Returns the strict canonical chunk bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        crate::codec::encode(self)
    }

    /// Decodes one chunk after enforcing its byte bound before allocation.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for oversized, malformed, noncanonical,
    /// or unsupported chunk encodings.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_STATISTICAL_EVIDENCE_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "statistical-evidence-chunk-bytes",
            });
        }
        crate::codec::decode(bytes)
    }

    /// Returns the digest a manifest records for this chunk.
    #[must_use]
    pub fn digest(&self) -> CampaignHash {
        CampaignHash::derive(
            STATISTICAL_EVIDENCE_CHUNK_DIGEST_DOMAIN,
            &self.canonical_bytes(),
        )
    }

    /// Derives every snapshot-root membership required by this chunk.
    ///
    /// The caller authenticates these against the manifest's snapshot before
    /// passing the chunk to [`StatisticalEvidenceVerifier::push_chunk`].
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when an object identity cannot be formed
    /// or two bodies claim different values for one root key.
    pub fn required_root_lookups(&self) -> Result<Vec<StatisticalRootLookup>, CampaignCodecError> {
        let mut lookups = BTreeMap::new();
        for item in &self.items {
            item.collect_lookups(&mut lookups)?;
        }
        finish_lookups(lookups)
    }
}

impl Canonical for StatisticalEvidenceChunk {
    fn encode(&self, encoder: &mut Encoder) {
        STATISTICAL_EVIDENCE_CHUNK_SCHEMA_VERSION.encode(encoder);
        self.index.encode(encoder);
        self.first_item.encode(encoder);
        self.items.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != STATISTICAL_EVIDENCE_CHUNK_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported statistical evidence chunk schema version",
            });
        }
        let index = u32::decode(decoder)?;
        let first_item = u64::decode(decoder)?;
        let items = decoder.sequence_bounded(
            MAX_STATISTICAL_EVIDENCE_ITEMS,
            "statistical-evidence-chunk-items",
            StatisticalEvidenceItem::decode,
        )?;
        if items.is_empty() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "statistical evidence chunk is empty",
            });
        }
        Ok(Self {
            index,
            first_item,
            items,
        })
    }
}

/// Manifest entry naming one chunk's position, item range, and digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatisticalEvidenceChunkDescriptor {
    index: u32,
    first_item: u64,
    item_count: u32,
    digest: CampaignHash,
}

impl StatisticalEvidenceChunkDescriptor {
    /// Describes an already-built chunk.
    #[must_use]
    pub fn of_chunk(chunk: &StatisticalEvidenceChunk) -> Self {
        Self {
            index: chunk.index,
            first_item: chunk.first_item,
            // Chunk construction bounds the item count by a `u32`-sized limit.
            item_count: u32::try_from(chunk.items.len()).unwrap_or(u32::MAX),
            digest: chunk.digest(),
        }
    }

    /// Returns the chunk's zero-based position.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// Returns the replay-order number of the chunk's first item.
    #[must_use]
    pub const fn first_item(&self) -> u64 {
        self.first_item
    }

    /// Returns how many items the chunk carries.
    #[must_use]
    pub const fn item_count(&self) -> u32 {
        self.item_count
    }

    /// Returns the digest of the chunk's canonical bytes.
    #[must_use]
    pub const fn digest(&self) -> CampaignHash {
        self.digest
    }
}

impl Canonical for StatisticalEvidenceChunkDescriptor {
    fn encode(&self, encoder: &mut Encoder) {
        self.index.encode(encoder);
        self.first_item.encode(encoder);
        self.item_count.encode(encoder);
        self.digest.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            index: u32::decode(decoder)?,
            first_item: u64::decode(decoder)?,
            item_count: u32::decode(decoder)?,
            digest: CampaignHash::decode(decoder)?,
        })
    }
}

/// Snapshot-bound manifest for one chunked statistical evidence stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatisticalEvidenceManifest {
    snapshot: CampaignSnapshot,
    planning_view: CampaignPlanningView,
    policy: CampaignPolicy,
    lineage: CampaignLineage,
    item_count: u64,
    chunks: Vec<StatisticalEvidenceChunkDescriptor>,
}

impl StatisticalEvidenceManifest {
    /// Builds a manifest after checking that its chunks tile the item range.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the chunks are out of order, leave a
    /// gap, overlap, exceed their bounds, or the manifest is oversized.
    pub fn new(
        snapshot: CampaignSnapshot,
        planning_view: CampaignPlanningView,
        policy: CampaignPolicy,
        lineage: CampaignLineage,
        item_count: u64,
        chunks: Vec<StatisticalEvidenceChunkDescriptor>,
    ) -> Result<Self, CampaignCodecError> {
        let manifest = Self {
            snapshot,
            planning_view,
            policy,
            lineage,
            item_count,
            chunks,
        };
        manifest.validate_tiling()?;
        crate::codec::ensure_encoded_size(
            &manifest,
            MAX_STATISTICAL_EVIDENCE_BYTES,
            "statistical-evidence-manifest-bytes",
        )?;
        Ok(manifest)
    }

    fn validate_tiling(&self) -> Result<(), CampaignCodecError> {
        if self.chunks.is_empty() || self.chunks.len() > MAX_STATISTICAL_EVIDENCE_CHUNKS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "statistical-evidence-manifest-chunks",
            });
        }
        let mut next_item = 0_u64;
        for (position, chunk) in self.chunks.iter().enumerate() {
            let item_count = usize::try_from(chunk.item_count).unwrap_or(usize::MAX);
            if usize::try_from(chunk.index).ok() != Some(position)
                || chunk.first_item != next_item
                || item_count == 0
                || item_count > MAX_STATISTICAL_EVIDENCE_ITEMS
            {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "statistical evidence chunks do not tile the item range",
                });
            }
            next_item = next_item.checked_add(u64::from(chunk.item_count)).ok_or(
                CampaignCodecError::InvalidValue {
                    reason: "statistical evidence item count overflows",
                },
            )?;
        }
        if next_item != self.item_count {
            return Err(CampaignCodecError::InvalidValue {
                reason: "statistical evidence chunks do not tile the item range",
            });
        }
        Ok(())
    }

    /// Returns the pinned snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &CampaignSnapshot {
        &self.snapshot
    }

    /// Returns the planning view embedded in the pinned snapshot.
    #[must_use]
    pub const fn planning_view(&self) -> &CampaignPlanningView {
        &self.planning_view
    }

    /// Returns the active policy.
    #[must_use]
    pub const fn policy(&self) -> &CampaignPolicy {
        &self.policy
    }

    /// Returns the campaign lineage.
    #[must_use]
    pub const fn lineage(&self) -> &CampaignLineage {
        &self.lineage
    }

    /// Returns the total number of draws and transitions.
    #[must_use]
    pub const fn item_count(&self) -> u64 {
        self.item_count
    }

    /// Returns the chunk descriptors in replay order.
    #[must_use]
    pub fn chunks(&self) -> &[StatisticalEvidenceChunkDescriptor] {
        &self.chunks
    }

    /// Returns the strict canonical manifest bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        crate::codec::encode(self)
    }

    /// Decodes one manifest after enforcing its byte bound before allocation.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for oversized, malformed, noncanonical,
    /// unsupported, or non-tiling manifests.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_STATISTICAL_EVIDENCE_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "statistical-evidence-manifest-bytes",
            });
        }
        crate::codec::decode(bytes)
    }
}

impl Canonical for StatisticalEvidenceManifest {
    fn encode(&self, encoder: &mut Encoder) {
        STATISTICAL_EVIDENCE_MANIFEST_SCHEMA_VERSION.encode(encoder);
        self.snapshot.encode(encoder);
        self.planning_view.encode(encoder);
        self.policy.encode(encoder);
        self.lineage.encode(encoder);
        self.item_count.encode(encoder);
        self.chunks.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != STATISTICAL_EVIDENCE_MANIFEST_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported statistical evidence manifest schema version",
            });
        }
        let manifest = Self {
            snapshot: CampaignSnapshot::decode(decoder)?,
            planning_view: CampaignPlanningView::decode(decoder)?,
            policy: CampaignPolicy::decode(decoder)?,
            lineage: CampaignLineage::decode(decoder)?,
            item_count: u64::decode(decoder)?,
            chunks: decoder.sequence_bounded(
                MAX_STATISTICAL_EVIDENCE_CHUNKS,
                "statistical-evidence-manifest-chunks",
                StatisticalEvidenceChunkDescriptor::decode,
            )?,
        };
        manifest.validate_tiling()?;
        Ok(manifest)
    }
}

/// Estimate produced by verifying a complete chunked evidence stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatisticalEvidenceReport {
    /// A finite statistical policy's endpoint estimate.
    Finite(StatisticalEstimateReport),
    /// A sequential Monte Carlo policy's final-population estimate.
    SequentialMonteCarlo(SequentialMonteCarloEstimateReport),
}

enum EvidenceReplay<'a> {
    Finite(FiniteEvidenceReplay<'a>),
    SequentialMonteCarlo(Box<SmcEvidenceReplay<'a>>),
}

/// In-order verifier for one chunked statistical evidence stream.
///
/// The verifier holds the manifest and bounded replay state only. Chunks are
/// pushed one at a time in manifest order; each must match its descriptor's
/// position, item range, and digest before its items are replayed.
///
/// # Examples
///
/// ```no_run
/// # fn fetch_chunk(
/// #     _: &crucible_campaign::StatisticalEvidenceChunkDescriptor,
/// # ) -> crucible_campaign::StatisticalEvidenceChunk { unimplemented!() }
/// # fn run(
/// #     manifest: &crucible_campaign::StatisticalEvidenceManifest,
/// # ) -> Result<(), crucible_campaign::CampaignCodecError> {
/// use crucible_campaign::StatisticalEvidenceVerifier;
///
/// let mut verifier = StatisticalEvidenceVerifier::new(manifest)?;
/// for descriptor in manifest.chunks() {
///     let chunk = fetch_chunk(descriptor);
///     // Authenticate chunk.required_root_lookups() against the snapshot here.
///     verifier.push_chunk(&chunk)?;
/// }
/// let report = verifier.finish()?;
/// # let _ = report;
/// # Ok(())
/// # }
/// ```
pub struct StatisticalEvidenceVerifier<'a> {
    manifest: &'a StatisticalEvidenceManifest,
    next_chunk: usize,
    replay: EvidenceReplay<'a>,
}

impl<'a> StatisticalEvidenceVerifier<'a> {
    /// Starts verification after checking the manifest against its policy.
    ///
    /// The caller must already have authenticated the manifest's snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the snapshot, policy, and lineage
    /// basis is inconsistent or the item count disagrees with the policy.
    pub fn new(manifest: &'a StatisticalEvidenceManifest) -> Result<Self, CampaignCodecError> {
        let basis = EvidenceBasis::new(
            &manifest.snapshot,
            &manifest.planning_view,
            &manifest.policy,
            &manifest.lineage,
        );
        if manifest.item_count != statistical_evidence_item_count(&manifest.policy)? {
            return Err(CampaignCodecError::InvalidValue {
                reason: "statistical evidence item count disagrees with its policy",
            });
        }
        let replay = if manifest.policy.sequential_monte_carlo_design().is_some() {
            EvidenceReplay::SequentialMonteCarlo(Box::new(SmcEvidenceReplay::new(basis)?))
        } else {
            EvidenceReplay::Finite(FiniteEvidenceReplay::new(basis, false)?)
        };
        Ok(Self {
            manifest,
            next_chunk: 0,
            replay,
        })
    }

    /// Verifies the next chunk in manifest order.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the chunk is unexpected, does not
    /// match its descriptor, or any item fails semantic replay.
    pub fn push_chunk(
        &mut self,
        chunk: &StatisticalEvidenceChunk,
    ) -> Result<(), CampaignCodecError> {
        let descriptor =
            self.manifest
                .chunks
                .get(self.next_chunk)
                .ok_or(CampaignCodecError::InvalidValue {
                    reason: "statistical evidence chunk is not in its manifest",
                })?;
        if StatisticalEvidenceChunkDescriptor::of_chunk(chunk) != *descriptor {
            return Err(CampaignCodecError::InvalidValue {
                reason: "statistical evidence chunk does not match its manifest",
            });
        }
        for item in &chunk.items {
            match (&mut self.replay, item) {
                (EvidenceReplay::Finite(replay), StatisticalEvidenceItem::Draw(draw)) => {
                    replay.push(draw)?;
                }
                (EvidenceReplay::Finite(_), StatisticalEvidenceItem::Transition(_)) => {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "finite statistical evidence contains an SMC transition",
                    });
                }
                (
                    EvidenceReplay::SequentialMonteCarlo(replay),
                    StatisticalEvidenceItem::Draw(draw),
                ) => replay.push_initial_draw(draw)?,
                (
                    EvidenceReplay::SequentialMonteCarlo(replay),
                    StatisticalEvidenceItem::Transition(transition),
                ) => replay.push_transition(transition)?,
            }
        }
        self.next_chunk += 1;
        Ok(())
    }

    /// Completes verification and returns the replayed estimate.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when a chunk is missing or the replayed
    /// population is incomplete or inconsistent.
    pub fn finish(self) -> Result<StatisticalEvidenceReport, CampaignCodecError> {
        if self.next_chunk != self.manifest.chunks.len() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "statistical evidence chunk is missing",
            });
        }
        match self.replay {
            EvidenceReplay::Finite(replay) => {
                replay.finish().map(StatisticalEvidenceReport::Finite)
            }
            EvidenceReplay::SequentialMonteCarlo(replay) => replay
                .finish()
                .map(StatisticalEvidenceReport::SequentialMonteCarlo),
        }
    }
}

/// Returns the number of evidence items a complete run of `policy` produces.
///
/// # Errors
///
/// Returns [`CampaignCodecError`] when the policy has no statistical design or
/// the count overflows.
pub(crate) fn statistical_evidence_item_count(
    policy: &CampaignPolicy,
) -> Result<u64, CampaignCodecError> {
    let draws = policy
        .statistical_sampling_design()
        .map(|design| design.draws().len())
        .ok_or(CampaignCodecError::InvalidValue {
            reason: "statistical evidence policy lacks a sampling design",
        })?;
    let transitions = policy
        .sequential_monte_carlo_design()
        .map_or(Some(0), |design| {
            u64::try_from(design.stages().len())
                .ok()
                .and_then(|stages| stages.checked_mul(u64::from(design.particle_count())))
        });
    u64::try_from(draws)
        .ok()
        .zip(transitions)
        .and_then(|(draws, transitions)| draws.checked_add(transitions))
        .ok_or(CampaignCodecError::InvalidValue {
            reason: "statistical evidence item count overflows",
        })
}
