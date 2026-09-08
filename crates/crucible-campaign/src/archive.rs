//! Canonical partial and complete campaign archive inventories.
//!
//! An archive manifest records source provenance and a complete partition of
//! the source closure into selected and omitted objects. Inventory pages name
//! objects in their bodies rather than as generic envelope children. This is
//! the explicit boundary that permits a partial archive to retain an object
//! without claiming that every descendant of that object is present.
//!
//! ```text
//! CampaignArchiveManifestV1
//!   source snapshot + policy + exact-checkpoint selections
//!   selected-page-00000000 -> CampaignArchiveInventoryPageV1(Selected, entries...)
//!   omitted-page-00000000  -> CampaignArchiveInventoryPageV1(Omitted, entries...)
//!   selected/omitted counts + ordered-entry digests
//! ```

use std::collections::BTreeSet;

use crucible_cas::content_store::{
    ContentId, ObjectProfile, Reconstructibility, RetentionRole, SensitivityClass,
};

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::{
    CampaignArchiveInventoryPageId, CampaignArchiveManifestId, CampaignCodecError, CampaignFactId,
    CampaignHash, CampaignSnapshotId, ConfigurationId, ExactCheckpointId,
};

/// Trusted resolver for live exact-pin materializations during archive planning.
///
/// Implementations hold the daemon's exact-pin retention fence and validate
/// the returned checkpoint through its exact-checkpoint store before returning.
/// The resolver must reject a stale pin fact, foreign campaign selection, or a
/// checkpoint whose authenticated manifest names another configuration.
pub trait CampaignArchiveCheckpointResolver {
    /// Resolves and validates the checkpoint selected for one live exact pin.
    ///
    /// # Errors
    ///
    /// Returns [`crate::CampaignRepositoryError`] when no exact current
    /// selection exists or its checkpoint cannot be authenticated for
    /// `configuration`.
    fn resolve_checkpoint(
        &mut self,
        configuration: ConfigurationId,
        pin_fact: CampaignFactId,
    ) -> Result<ExactCheckpointId, crate::CampaignRepositoryError>;
}

const ARCHIVE_SCHEMA_VERSION: u32 = 1;

/// Maximum direct object entries carried by one archive inventory page.
pub const MAX_ARCHIVE_INVENTORY_PAGE_ENTRIES: usize = 4_096;
/// Maximum selected plus omitted objects represented by one archive.
pub const MAX_ARCHIVE_INVENTORY_ENTRIES: usize = crate::MAX_CAMPAIGN_CLOSURE_OBJECTS;

/// Closed archive selection policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignArchivePolicy {
    /// Retains canonical campaign metadata only.
    Metadata,
    /// Retains metadata, findings, evidence, and configuration artifacts.
    Findings,
    /// Retains a findings archive plus exact state reachable from finding roots.
    Debug,
    /// Retains the complete source snapshot closure required for offline resume.
    Executable,
    /// Retains the complete source closure plus caller-declared retained roots.
    Mirror,
}

impl Canonical for CampaignArchivePolicy {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::Metadata => 0,
            Self::Findings => 1,
            Self::Debug => 2,
            Self::Executable => 3,
            Self::Mirror => 4,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Metadata),
            1 => Ok(Self::Findings),
            2 => Ok(Self::Debug),
            3 => Ok(Self::Executable),
            4 => Ok(Self::Mirror),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "campaign-archive-policy",
                tag,
            }),
        }
    }
}

/// Declares whether one page contains selected or omitted source objects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveInventoryDisposition {
    /// Objects that belong to the transferable archive inventory.
    Selected,
    /// Objects deliberately excluded by the archive policy.
    Omitted,
}

/// Exact materialization selected for one live exact semantic pin.
///
/// The daemon derives this tuple while holding its exact-pin catalog fence.
/// Archive planning compares every tuple with the source snapshot's
/// authenticated semantic pin projection before admitting its checkpoint root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CampaignArchiveCheckpointSelection {
    configuration: ConfigurationId,
    pin_fact: CampaignFactId,
    checkpoint: ExactCheckpointId,
}

impl CampaignArchiveCheckpointSelection {
    /// Builds one catalog-authenticated exact-pin materialization selection.
    #[must_use]
    pub(crate) const fn new(
        configuration: ConfigurationId,
        pin_fact: CampaignFactId,
        checkpoint: ExactCheckpointId,
    ) -> Self {
        Self {
            configuration,
            pin_fact,
            checkpoint,
        }
    }

    /// Returns the semantic configuration owned by the pin.
    #[must_use]
    pub const fn configuration(self) -> ConfigurationId {
        self.configuration
    }

    /// Returns the latest authenticated exact-pin fact.
    #[must_use]
    pub const fn pin_fact(self) -> CampaignFactId {
        self.pin_fact
    }

    /// Returns the selected portable exact-checkpoint root.
    #[must_use]
    pub const fn checkpoint(self) -> ExactCheckpointId {
        self.checkpoint
    }
}

impl Canonical for CampaignArchiveCheckpointSelection {
    fn encode(&self, encoder: &mut Encoder) {
        self.configuration.encode(encoder);
        self.pin_fact.encode(encoder);
        self.checkpoint.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            configuration: ConfigurationId::decode(decoder)?,
            pin_fact: CampaignFactId::decode(decoder)?,
            checkpoint: ExactCheckpointId::decode(decoder)?,
        })
    }
}

impl Canonical for ArchiveInventoryDisposition {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::Selected => 0,
            Self::Omitted => 1,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Selected),
            1 => Ok(Self::Omitted),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "campaign-archive-inventory-disposition",
                tag,
            }),
        }
    }
}

/// Authenticated profile and length for one archive object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ArchiveObjectEntry {
    id: ContentId,
    logical_length: u64,
    sensitivity: SensitivityClass,
    reconstructibility: Reconstructibility,
    retention_role: RetentionRole,
}

impl ArchiveObjectEntry {
    pub(crate) fn from_profile(id: ContentId, profile: ObjectProfile) -> Self {
        Self {
            id,
            logical_length: profile.logical_length(),
            sensitivity: profile.sensitivity(),
            reconstructibility: profile.reconstructibility(),
            retention_role: profile.retention_role(),
        }
    }

    /// Returns the exact logical object identity.
    #[must_use]
    pub const fn id(self) -> ContentId {
        self.id
    }

    /// Returns the authenticated logical byte length.
    #[must_use]
    pub const fn logical_length(self) -> u64 {
        self.logical_length
    }

    /// Returns the authenticated sensitivity class.
    #[must_use]
    pub const fn sensitivity(self) -> SensitivityClass {
        self.sensitivity
    }

    /// Returns the authenticated reconstruction class.
    #[must_use]
    pub const fn reconstructibility(self) -> Reconstructibility {
        self.reconstructibility
    }

    /// Returns the authenticated retention role.
    #[must_use]
    pub const fn retention_role(self) -> RetentionRole {
        self.retention_role
    }

    pub(crate) fn matches_profile(self, profile: ObjectProfile) -> bool {
        self.id.kind() == profile.kind()
            && self.logical_length == profile.logical_length()
            && self.sensitivity == profile.sensitivity()
            && self.reconstructibility == profile.reconstructibility()
            && self.retention_role == profile.retention_role()
    }
}

impl Canonical for ArchiveObjectEntry {
    fn encode(&self, encoder: &mut Encoder) {
        Canonical::encode(&self.id, encoder);
        self.logical_length.encode(encoder);
        encode_sensitivity(self.sensitivity, encoder);
        encode_reconstructibility(self.reconstructibility, encoder);
        encode_retention_role(self.retention_role, encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            id: ContentId::decode(decoder)?,
            logical_length: u64::decode(decoder)?,
            sensitivity: decode_sensitivity(decoder)?,
            reconstructibility: decode_reconstructibility(decoder)?,
            retention_role: decode_retention_role(decoder)?,
        })
    }
}

/// One bounded canonical page of a direct archive inventory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignArchiveInventoryPage {
    schema_version: u32,
    disposition: ArchiveInventoryDisposition,
    ordinal: u32,
    entries: Vec<ArchiveObjectEntry>,
}

impl CampaignArchiveInventoryPage {
    pub(crate) fn new(
        disposition: ArchiveInventoryDisposition,
        ordinal: u32,
        entries: Vec<ArchiveObjectEntry>,
    ) -> Result<Self, CampaignCodecError> {
        let page = Self {
            schema_version: ARCHIVE_SCHEMA_VERSION,
            disposition,
            ordinal,
            entries,
        };
        page.validate()?;
        Ok(page)
    }

    pub(crate) const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns whether this page declares selected or omitted objects.
    #[must_use]
    pub const fn disposition(&self) -> ArchiveInventoryDisposition {
        self.disposition
    }

    /// Returns the zero-based ordinal within its disposition.
    #[must_use]
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    /// Returns entries in strict content-ID order.
    #[must_use]
    pub fn entries(&self) -> &[ArchiveObjectEntry] {
        &self.entries
    }

    /// Returns strict canonical page bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes and validates one strict canonical page.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for invalid framing, order, or bounds.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        let page = codec::decode::<Self>(bytes)?;
        page.validate()?;
        Ok(page)
    }

    /// Returns the page's typed content identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if envelope construction fails.
    pub fn id(&self) -> Result<CampaignArchiveInventoryPageId, CampaignCodecError> {
        let envelope = crate::ObjectEnvelope::for_archive_inventory_page(self)?;
        CampaignArchiveInventoryPageId::from_content_id(envelope.content_id())
    }

    fn validate(&self) -> Result<(), CampaignCodecError> {
        if self.schema_version != ARCHIVE_SCHEMA_VERSION {
            return Err(invalid(
                "archive inventory page schema version is unsupported",
            ));
        }
        if self.entries.is_empty() || self.entries.len() > MAX_ARCHIVE_INVENTORY_PAGE_ENTRIES {
            return Err(invalid("archive inventory page entry count is invalid"));
        }
        if self.entries.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            return Err(invalid(
                "archive inventory page entries are not strictly ordered",
            ));
        }
        Ok(())
    }
}

impl Canonical for CampaignArchiveInventoryPage {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.disposition.encode(encoder);
        self.ordinal.encode(encoder);
        self.entries.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            schema_version: u32::decode(decoder)?,
            disposition: ArchiveInventoryDisposition::decode(decoder)?,
            ordinal: u32::decode(decoder)?,
            entries: Vec::<ArchiveObjectEntry>::decode(decoder)?,
        })
    }
}

/// Canonical root of a partial or complete campaign archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignArchiveManifest {
    schema_version: u32,
    source_snapshot: CampaignSnapshotId,
    policy: CampaignArchivePolicy,
    checkpoint_selections: Vec<CampaignArchiveCheckpointSelection>,
    retained_roots: Vec<ContentId>,
    selected_pages: Vec<CampaignArchiveInventoryPageId>,
    omitted_pages: Vec<CampaignArchiveInventoryPageId>,
    selected_count: u64,
    omitted_count: u64,
    selected_digest: CampaignHash,
    omitted_digest: CampaignHash,
}

impl CampaignArchiveManifest {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        source_snapshot: CampaignSnapshotId,
        policy: CampaignArchivePolicy,
        checkpoint_selections: Vec<CampaignArchiveCheckpointSelection>,
        retained_roots: Vec<ContentId>,
        selected_pages: Vec<CampaignArchiveInventoryPageId>,
        omitted_pages: Vec<CampaignArchiveInventoryPageId>,
        selected: &[ArchiveObjectEntry],
        omitted: &[ArchiveObjectEntry],
    ) -> Result<Self, CampaignCodecError> {
        let selected_count = u64::try_from(selected.len())
            .map_err(|_| invalid("archive selected count is unrepresentable"))?;
        let omitted_count = u64::try_from(omitted.len())
            .map_err(|_| invalid("archive omitted count is unrepresentable"))?;
        let manifest = Self {
            schema_version: ARCHIVE_SCHEMA_VERSION,
            source_snapshot,
            policy,
            checkpoint_selections,
            retained_roots,
            selected_pages,
            omitted_pages,
            selected_count,
            omitted_count,
            selected_digest: inventory_digest(selected),
            omitted_digest: inventory_digest(omitted),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub(crate) const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns the complete source snapshot used for selection.
    #[must_use]
    pub const fn source_snapshot(&self) -> CampaignSnapshotId {
        self.source_snapshot
    }

    /// Returns the archive selection policy.
    #[must_use]
    pub const fn policy(&self) -> CampaignArchivePolicy {
        self.policy
    }

    /// Returns exact checkpoint selections required by executable restoration.
    #[must_use]
    pub fn checkpoint_selections(&self) -> &[CampaignArchiveCheckpointSelection] {
        &self.checkpoint_selections
    }

    /// Returns additional closure roots retained by a mirror archive.
    #[must_use]
    pub fn retained_roots(&self) -> &[ContentId] {
        &self.retained_roots
    }

    /// Returns selected inventory pages in ordinal order.
    #[must_use]
    pub fn selected_pages(&self) -> &[CampaignArchiveInventoryPageId] {
        &self.selected_pages
    }

    /// Returns omitted inventory pages in ordinal order.
    #[must_use]
    pub fn omitted_pages(&self) -> &[CampaignArchiveInventoryPageId] {
        &self.omitted_pages
    }

    /// Returns the declared number of selected objects.
    #[must_use]
    pub const fn selected_count(&self) -> u64 {
        self.selected_count
    }

    /// Returns the declared number of omitted objects.
    #[must_use]
    pub const fn omitted_count(&self) -> u64 {
        self.omitted_count
    }

    pub(crate) const fn selected_digest(&self) -> CampaignHash {
        self.selected_digest
    }

    pub(crate) const fn omitted_digest(&self) -> CampaignHash {
        self.omitted_digest
    }

    /// Returns strict canonical manifest bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes and validates one strict canonical manifest.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for invalid framing, policy, or bounds.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        let manifest = codec::decode::<Self>(bytes)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Returns the manifest's typed content identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if envelope construction fails.
    pub fn id(&self) -> Result<CampaignArchiveManifestId, CampaignCodecError> {
        let envelope = crate::ObjectEnvelope::for_archive_manifest(self)?;
        CampaignArchiveManifestId::from_content_id(envelope.content_id())
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        self.selected_pages
            .iter()
            .enumerate()
            .map(|(ordinal, page)| (format!("selected-page-{ordinal:08}"), page.content_id()))
            .chain(
                self.omitted_pages
                    .iter()
                    .enumerate()
                    .map(|(ordinal, page)| {
                        (format!("omitted-page-{ordinal:08}"), page.content_id())
                    }),
            )
            .collect()
    }

    fn validate(&self) -> Result<(), CampaignCodecError> {
        if self.schema_version != ARCHIVE_SCHEMA_VERSION {
            return Err(invalid("archive manifest schema version is unsupported"));
        }
        if self.policy != CampaignArchivePolicy::Mirror && !self.retained_roots.is_empty() {
            return Err(invalid("only mirror archives may declare retained roots"));
        }
        if !matches!(
            self.policy,
            CampaignArchivePolicy::Executable | CampaignArchivePolicy::Mirror
        ) && !self.checkpoint_selections.is_empty()
        {
            return Err(invalid(
                "partial archives cannot declare operational checkpoint selections",
            ));
        }
        if self
            .checkpoint_selections
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid(
                "archive checkpoint selections are not strictly ordered",
            ));
        }
        if self.checkpoint_selections.windows(2).any(|pair| {
            pair[0].configuration == pair[1].configuration && pair[0].pin_fact == pair[1].pin_fact
        }) {
            return Err(invalid("archive checkpoint selection pair is duplicated"));
        }
        if self
            .retained_roots
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid("archive retained roots are not strictly ordered"));
        }
        let total = self
            .selected_count
            .checked_add(self.omitted_count)
            .ok_or_else(|| invalid("archive inventory count overflow"))?;
        if total == 0 || total > MAX_ARCHIVE_INVENTORY_ENTRIES as u64 {
            return Err(invalid("archive inventory count exceeds its bound"));
        }
        validate_page_count(self.selected_count, self.selected_pages.len())?;
        validate_page_count(self.omitted_count, self.omitted_pages.len())?;
        Ok(())
    }
}

impl Canonical for CampaignArchiveManifest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.source_snapshot.encode(encoder);
        self.policy.encode(encoder);
        self.checkpoint_selections.encode(encoder);
        self.retained_roots.encode(encoder);
        self.selected_pages.encode(encoder);
        self.omitted_pages.encode(encoder);
        self.selected_count.encode(encoder);
        self.omitted_count.encode(encoder);
        self.selected_digest.encode(encoder);
        self.omitted_digest.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            schema_version: u32::decode(decoder)?,
            source_snapshot: CampaignSnapshotId::decode(decoder)?,
            policy: CampaignArchivePolicy::decode(decoder)?,
            checkpoint_selections: Vec::<CampaignArchiveCheckpointSelection>::decode(decoder)?,
            retained_roots: Vec::<ContentId>::decode(decoder)?,
            selected_pages: Vec::<CampaignArchiveInventoryPageId>::decode(decoder)?,
            omitted_pages: Vec::<CampaignArchiveInventoryPageId>::decode(decoder)?,
            selected_count: u64::decode(decoder)?,
            omitted_count: u64::decode(decoder)?,
            selected_digest: CampaignHash::decode(decoder)?,
            omitted_digest: CampaignHash::decode(decoder)?,
        })
    }
}

/// Profiler-derived aggregate archive report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CampaignArchiveReport {
    /// Number of represented objects.
    pub objects: u64,
    /// Total authenticated logical bytes.
    pub logical_bytes: u64,
    /// Bytes classified as campaign metadata.
    pub metadata_bytes: u64,
    /// Bytes classified as evidence.
    pub evidence_bytes: u64,
    /// Bytes classified as guest state.
    pub guest_state_bytes: u64,
}

impl CampaignArchiveReport {
    pub(crate) fn add(&mut self, entry: ArchiveObjectEntry) -> Result<(), CampaignCodecError> {
        self.objects = self
            .objects
            .checked_add(1)
            .ok_or_else(|| invalid("archive report object count overflow"))?;
        self.logical_bytes = self
            .logical_bytes
            .checked_add(entry.logical_length)
            .ok_or_else(|| invalid("archive report byte count overflow"))?;
        let class_bytes = match entry.sensitivity {
            SensitivityClass::Metadata => &mut self.metadata_bytes,
            SensitivityClass::Evidence => &mut self.evidence_bytes,
            SensitivityClass::GuestState => &mut self.guest_state_bytes,
        };
        *class_bytes = class_bytes
            .checked_add(entry.logical_length)
            .ok_or_else(|| invalid("archive report class byte count overflow"))?;
        Ok(())
    }
}

/// Fully validated direct inventory for one archive manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignArchiveInspection {
    manifest_id: CampaignArchiveManifestId,
    manifest: CampaignArchiveManifest,
    selected: Vec<ArchiveObjectEntry>,
    omitted: Vec<ArchiveObjectEntry>,
    retained_objects: BTreeSet<ContentId>,
    selected_report: CampaignArchiveReport,
    omitted_report: CampaignArchiveReport,
    omitted_inventory_verified: bool,
}

impl CampaignArchiveInspection {
    /// Returns the authenticated manifest identity.
    #[must_use]
    pub const fn manifest_id(&self) -> CampaignArchiveManifestId {
        self.manifest_id
    }

    /// Returns the decoded archive manifest.
    #[must_use]
    pub const fn manifest(&self) -> &CampaignArchiveManifest {
        &self.manifest
    }

    /// Returns the direct selected inventory.
    #[must_use]
    pub fn selected(&self) -> &[ArchiveObjectEntry] {
        &self.selected
    }

    /// Returns the explicitly omitted source inventory.
    #[must_use]
    pub fn omitted(&self) -> &[ArchiveObjectEntry] {
        &self.omitted
    }

    /// Returns manifest, page, and selected-object IDs retained by archive GC.
    #[must_use]
    pub const fn retained_objects(&self) -> &BTreeSet<ContentId> {
        &self.retained_objects
    }

    /// Returns selected-object sensitivity and size totals.
    #[must_use]
    pub const fn selected_report(&self) -> CampaignArchiveReport {
        self.selected_report
    }

    /// Returns declared omitted-object sensitivity and size totals.
    #[must_use]
    pub const fn omitted_report(&self) -> CampaignArchiveReport {
        self.omitted_report
    }

    /// Returns whether every omitted object was available and independently profiled.
    ///
    /// A portable partial destination normally returns `false`: its omitted
    /// aggregate is an authenticated source declaration, while selected bytes
    /// remain independently authenticated at the destination.
    #[must_use]
    pub const fn omitted_inventory_verified(&self) -> bool {
        self.omitted_inventory_verified
    }
}

/// Effect-free archive selection and canonical manifest material.
#[derive(Clone, Debug)]
pub struct CampaignArchivePlan {
    pub(crate) manifest_id: CampaignArchiveManifestId,
    pub(crate) manifest: CampaignArchiveManifest,
    pub(crate) manifest_envelope: crate::ObjectEnvelope,
    pub(crate) page_envelopes: Vec<crate::ObjectEnvelope>,
    pub(crate) selected: Vec<ArchiveObjectEntry>,
    pub(crate) omitted: Vec<ArchiveObjectEntry>,
}

impl CampaignArchivePlan {
    /// Returns the canonical manifest identity.
    #[must_use]
    pub fn manifest_id(&self) -> CampaignArchiveManifestId {
        self.manifest_id
    }

    /// Returns the canonical archive manifest.
    #[must_use]
    pub const fn manifest(&self) -> &CampaignArchiveManifest {
        &self.manifest
    }

    /// Returns the selected direct-object inventory.
    #[must_use]
    pub fn selected(&self) -> &[ArchiveObjectEntry] {
        &self.selected
    }

    /// Returns the explicitly omitted source inventory.
    #[must_use]
    pub fn omitted(&self) -> &[ArchiveObjectEntry] {
        &self.omitted
    }

    /// Returns every object protected while this plan is being transferred.
    ///
    /// The inventory includes selected campaign objects plus canonical page and
    /// manifest objects. It is sorted and duplicate free.
    #[must_use]
    pub fn transfer_objects(&self) -> Vec<(ContentId, u64)> {
        let mut objects = self
            .selected
            .iter()
            .map(|entry| (entry.id(), entry.logical_length()))
            .collect::<BTreeSet<_>>();
        objects.extend(self.page_envelopes.iter().map(|envelope| {
            let bytes = envelope.canonical_bytes();
            (envelope.content_id(), bytes.len() as u64)
        }));
        let manifest_bytes = self.manifest_envelope.canonical_bytes();
        objects.insert((self.manifest_id.content_id(), manifest_bytes.len() as u64));
        objects.into_iter().collect()
    }
}

/// Result of one idempotent missing-object archive transfer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CampaignArchiveTransferReport {
    /// Objects copied during this call.
    pub copied_objects: u64,
    /// Authenticated objects already present at the destination.
    pub existing_objects: u64,
    /// Logical bytes copied during this call.
    pub copied_bytes: u64,
}

pub(crate) fn inventory_digest(entries: &[ArchiveObjectEntry]) -> CampaignHash {
    CampaignHash::derive(
        "crucible.campaign.archive-inventory.v1",
        &codec::encode(&entries.to_vec()),
    )
}

pub(crate) fn build_inspection(
    manifest_id: CampaignArchiveManifestId,
    manifest: CampaignArchiveManifest,
    selected: Vec<ArchiveObjectEntry>,
    omitted: Vec<ArchiveObjectEntry>,
    page_ids: impl IntoIterator<Item = ContentId>,
    omitted_inventory_verified: bool,
) -> Result<CampaignArchiveInspection, CampaignCodecError> {
    if manifest.selected_count != selected.len() as u64
        || manifest.omitted_count != omitted.len() as u64
        || manifest.selected_digest != inventory_digest(&selected)
        || manifest.omitted_digest != inventory_digest(&omitted)
    {
        return Err(invalid("archive inventory does not match its manifest"));
    }
    if selected
        .iter()
        .map(|entry| entry.id)
        .collect::<BTreeSet<_>>()
        .intersection(&omitted.iter().map(|entry| entry.id).collect())
        .next()
        .is_some()
    {
        return Err(invalid("archive selected and omitted inventories overlap"));
    }

    let mut retained_objects = page_ids.into_iter().collect::<BTreeSet<_>>();
    retained_objects.insert(manifest_id.content_id());
    retained_objects.extend(selected.iter().map(|entry| entry.id));

    let mut selected_report = CampaignArchiveReport::default();
    for entry in &selected {
        selected_report.add(*entry)?;
    }
    let mut omitted_report = CampaignArchiveReport::default();
    for entry in &omitted {
        omitted_report.add(*entry)?;
    }
    Ok(CampaignArchiveInspection {
        manifest_id,
        manifest,
        selected,
        omitted,
        retained_objects,
        selected_report,
        omitted_report,
        omitted_inventory_verified,
    })
}

fn validate_page_count(count: u64, pages: usize) -> Result<(), CampaignCodecError> {
    let expected = if count == 0 {
        0
    } else {
        ((count - 1) / MAX_ARCHIVE_INVENTORY_PAGE_ENTRIES as u64) + 1
    };
    if pages as u64 != expected {
        return Err(invalid("archive inventory page count is inconsistent"));
    }
    Ok(())
}

fn encode_sensitivity(value: SensitivityClass, encoder: &mut Encoder) {
    encoder.u8(match value {
        SensitivityClass::Metadata => 0,
        SensitivityClass::Evidence => 1,
        SensitivityClass::GuestState => 2,
    });
}

fn decode_sensitivity(decoder: &mut Decoder<'_>) -> Result<SensitivityClass, CampaignCodecError> {
    match decoder.u8()? {
        0 => Ok(SensitivityClass::Metadata),
        1 => Ok(SensitivityClass::Evidence),
        2 => Ok(SensitivityClass::GuestState),
        tag => Err(CampaignCodecError::UnknownTag {
            kind: "archive-sensitivity-class",
            tag,
        }),
    }
}

fn encode_reconstructibility(value: Reconstructibility, encoder: &mut Encoder) {
    encoder.u8(match value {
        Reconstructibility::Canonical => 0,
        Reconstructibility::Rebuildable => 1,
    });
}

fn decode_reconstructibility(
    decoder: &mut Decoder<'_>,
) -> Result<Reconstructibility, CampaignCodecError> {
    match decoder.u8()? {
        0 => Ok(Reconstructibility::Canonical),
        1 => Ok(Reconstructibility::Rebuildable),
        tag => Err(CampaignCodecError::UnknownTag {
            kind: "archive-reconstructibility",
            tag,
        }),
    }
}

fn encode_retention_role(value: RetentionRole, encoder: &mut Encoder) {
    encoder.u8(match value {
        RetentionRole::CampaignMetadata => 0,
        RetentionRole::Evidence => 1,
        RetentionRole::ExactState => 2,
        RetentionRole::ProjectionCache => 3,
    });
}

fn decode_retention_role(decoder: &mut Decoder<'_>) -> Result<RetentionRole, CampaignCodecError> {
    match decoder.u8()? {
        0 => Ok(RetentionRole::CampaignMetadata),
        1 => Ok(RetentionRole::Evidence),
        2 => Ok(RetentionRole::ExactState),
        3 => Ok(RetentionRole::ProjectionCache),
        tag => Err(CampaignCodecError::UnknownTag {
            kind: "archive-retention-role",
            tag,
        }),
    }
}

const fn invalid(reason: &'static str) -> CampaignCodecError {
    CampaignCodecError::InvalidValue { reason }
}
