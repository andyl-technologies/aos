//! Bounded one-way migration of historical campaign repository heads.
//!
//! Normal repository reads admit only the current snapshot, ledger, admission,
//! and measurement schemas. This module is the sole owner of historical body
//! decoders. A migration authenticates and charges the complete old closure,
//! rewrites every affected identity, validates the complete current closure,
//! and advances the named ref with one final compare-and-swap.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crucible_cas::content_store::{ContentId, ObjectKind, RefCasOutcome};

use super::*;
use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::{CampaignBudgetLedger, CampaignRoots};

mod legacy;

#[cfg(test)]
mod tests;

use legacy::{LegacyAttemptAdmission, LegacyAttemptAdmissionFact, LegacyCampaignSnapshot};

const MIGRATION_MAP_PAGE_ITEMS: usize = 10_000;

/// Identifies one historical version-two campaign snapshot admitted for migration.
///
/// This identity is accepted only by [`CampaignRepository::migrate_legacy_campaign`].
/// Normal campaign APIs use [`CampaignSnapshotId`], whose current-only schema
/// admission prevents a historical head from entering query, planning, or mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CampaignMigrationHead(ContentId);

impl CampaignMigrationHead {
    /// Claims a historical snapshot identity for the offline migrator.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] unless `value` identifies a
    /// version-two campaign snapshot.
    pub fn from_content_id(value: ContentId) -> Result<Self, CampaignCodecError> {
        if value.kind() != ObjectKind::CampaignSnapshot || value.schema_version() != 2 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "migration head is not a version-two campaign snapshot",
            });
        }
        Ok(Self(value))
    }

    /// Parses a canonical historical campaign snapshot identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed text, the wrong record tag,
    /// or a content identity outside the sole migratable snapshot schema.
    pub fn parse(value: &str) -> Result<Self, CampaignCodecError> {
        let (tag, encoded_content) =
            value
                .split_once('@')
                .ok_or(CampaignCodecError::InvalidValue {
                    reason: "migration head identity is malformed",
                })?;
        if tag != "crucible.campaign.snapshot" {
            return Err(CampaignCodecError::InvalidValue {
                reason: "migration head identity has the wrong record type",
            });
        }
        let content =
            ContentId::parse(encoded_content).map_err(|_| CampaignCodecError::InvalidValue {
                reason: "migration head identity is malformed",
            })?;
        Self::from_content_id(content)
    }

    /// Returns the historical content identity.
    #[must_use]
    pub const fn content_id(self) -> ContentId {
        self.0
    }

    /// Renders the canonical record-typed identity accepted by store repair.
    #[must_use]
    pub fn to_text(self) -> String {
        format!("crucible.campaign.snapshot@{}", self.0.encode())
    }
}

impl fmt::Display for CampaignMigrationHead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_text())
    }
}

impl Canonical for CampaignMigrationHead {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.string("crucible.campaign.snapshot");
        Canonical::encode(&self.0, encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if decoder.string_bounded(
            "crucible.campaign.snapshot".len(),
            "migration-head-identity-tag-bytes",
        )? != "crucible.campaign.snapshot"
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "migration head identity has the wrong record type",
            });
        }
        Self::from_content_id(ContentId::decode(decoder)?)
    }
}

/// Identifies one independently bounded campaign-migration resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignMigrationLimit {
    /// Unique objects read from the historical closure.
    InputObjects,
    /// Aggregate canonical bytes read from the historical closure.
    InputBytes,
    /// Canonical bytes in any single input or output object.
    ObjectBytes,
    /// Unique objects reachable from the translated closure.
    OutputObjects,
    /// Aggregate canonical bytes reachable from the translated closure.
    OutputBytes,
    /// Entries decoded and reinserted while translating Merkle maps.
    MapEntries,
    /// Linear campaign snapshots traversed from the old head.
    Ancestry,
}

impl fmt::Display for CampaignMigrationLimit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InputObjects => "input-object",
            Self::InputBytes => "input-byte",
            Self::ObjectBytes => "per-object-byte",
            Self::OutputObjects => "output-object",
            Self::OutputBytes => "output-byte",
            Self::MapEntries => "map-entry",
            Self::Ancestry => "ancestry",
        })
    }
}

/// Caller-admitted resource bounds for one offline campaign migration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignMigrationBudget {
    maximum_objects: usize,
    maximum_input_bytes: u64,
    maximum_output_bytes: u64,
    maximum_object_bytes: u64,
    maximum_ancestry: usize,
}

impl CampaignMigrationBudget {
    /// Builds a complete nonzero migration budget.
    ///
    /// `maximum_objects` independently bounds input objects, output objects,
    /// and translated map entries. Byte totals include canonical envelopes.
    ///
    /// # Errors
    ///
    /// Returns an invalid-request error when any bound is zero or the per-object
    /// bound exceeds either aggregate byte bound.
    pub fn new(
        maximum_objects: usize,
        maximum_input_bytes: u64,
        maximum_output_bytes: u64,
        maximum_object_bytes: u64,
        maximum_ancestry: usize,
    ) -> Result<Self, CampaignRepositoryError> {
        if maximum_objects == 0
            || maximum_input_bytes == 0
            || maximum_output_bytes == 0
            || maximum_object_bytes == 0
            || maximum_ancestry == 0
            || maximum_object_bytes > maximum_input_bytes
            || maximum_object_bytes > maximum_output_bytes
        {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "campaign-migration-budget-is-invalid",
            });
        }
        Ok(Self {
            maximum_objects,
            maximum_input_bytes,
            maximum_output_bytes,
            maximum_object_bytes,
            maximum_ancestry,
        })
    }

    /// Returns the independent input, output, and map-entry object bound.
    #[must_use]
    pub const fn maximum_objects(self) -> usize {
        self.maximum_objects
    }

    /// Returns the aggregate input-envelope byte bound.
    #[must_use]
    pub const fn maximum_input_bytes(self) -> u64 {
        self.maximum_input_bytes
    }

    /// Returns the aggregate output-envelope byte bound.
    #[must_use]
    pub const fn maximum_output_bytes(self) -> u64 {
        self.maximum_output_bytes
    }

    /// Returns the maximum bytes admitted for one envelope.
    #[must_use]
    pub const fn maximum_object_bytes(self) -> u64 {
        self.maximum_object_bytes
    }

    /// Returns the maximum number of snapshots in the migrated ancestry.
    #[must_use]
    pub const fn maximum_ancestry(self) -> usize {
        self.maximum_ancestry
    }
}

/// Exact request for one offline, compare-and-swap campaign migration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignMigrationRequest {
    name: String,
    expected_head: CampaignMigrationHead,
    budget: CampaignMigrationBudget,
}

impl CampaignMigrationRequest {
    /// Builds a bounded migration request for one exact stored head.
    ///
    /// # Errors
    ///
    /// Returns an invalid-ref error when `name` is not a canonical campaign name.
    pub fn new(
        name: impl Into<String>,
        expected_head: CampaignMigrationHead,
        budget: CampaignMigrationBudget,
    ) -> Result<Self, CampaignRepositoryError> {
        let name = name.into();
        campaign_ref(&name)?;
        Ok(Self {
            name,
            expected_head,
            budget,
        })
    }

    /// Returns the named campaign to migrate.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the exact historical head admitted by the caller.
    #[must_use]
    pub const fn expected_head(&self) -> CampaignMigrationHead {
        self.expected_head
    }

    /// Returns the complete migration resource budget.
    #[must_use]
    pub const fn budget(&self) -> CampaignMigrationBudget {
        self.budget
    }
}

/// Auditable result of one committed campaign migration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignMigrationResult {
    prior_head: CampaignMigrationHead,
    new_head: CampaignSnapshotId,
    input_objects: usize,
    input_bytes: u64,
    output_objects: usize,
    output_bytes: u64,
    mapped_entries: usize,
    ancestry: usize,
}

impl CampaignMigrationResult {
    /// Returns the historical head replaced by the migration.
    #[must_use]
    pub const fn prior_head(self) -> CampaignMigrationHead {
        self.prior_head
    }

    /// Returns the fully validated current head installed by the migration.
    #[must_use]
    pub const fn new_head(self) -> CampaignSnapshotId {
        self.new_head
    }

    /// Returns unique input objects authenticated during preflight.
    #[must_use]
    pub const fn input_objects(self) -> usize {
        self.input_objects
    }

    /// Returns aggregate canonical input bytes authenticated during preflight.
    #[must_use]
    pub const fn input_bytes(self) -> u64 {
        self.input_bytes
    }

    /// Returns unique objects authenticated in the translated closure.
    #[must_use]
    pub const fn output_objects(self) -> usize {
        self.output_objects
    }

    /// Returns aggregate canonical bytes authenticated in the translated closure.
    #[must_use]
    pub const fn output_bytes(self) -> u64 {
        self.output_bytes
    }

    /// Returns Merkle entries decoded and reinserted during translation.
    #[must_use]
    pub const fn mapped_entries(self) -> usize {
        self.mapped_entries
    }

    /// Returns the number of translated snapshots.
    #[must_use]
    pub const fn ancestry(self) -> usize {
        self.ancestry
    }
}

#[derive(Default)]
struct MigrationCharge {
    input_objects: usize,
    input_bytes: u64,
    output_objects: usize,
    output_bytes: u64,
    mapped_entries: usize,
    ancestry: usize,
}

impl CampaignRepository {
    /// Migrates one exact historical campaign head to the current store schema.
    ///
    /// This is an offline repair mutation. Normal query, planning, and mutation
    /// entry points reject the historical head. The method holds the repository
    /// mutation and publication guard, authenticates the complete old closure,
    /// rewrites the full immutable ancestry with an old-to-new identity map,
    /// validates the resulting current closure, and advances the mutable ref last.
    /// A compare-and-swap conflict may leave unreachable immutable objects for GC.
    ///
    /// Historical claimed measurement maps are rejected because no canonical
    /// execution-model evaluation can be reconstructed from them.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale ref, malformed or unsupported historical
    /// data, exhausted migration budget, incomplete translated closure, or a
    /// final compare-and-swap conflict. The named ref is unchanged on failure.
    pub fn migrate_legacy_campaign(
        &self,
        request: CampaignMigrationRequest,
    ) -> Result<CampaignMigrationResult, CampaignRepositoryError> {
        let _guard = self.lock_mutation()?;
        let campaign_ref = campaign_ref(request.name())?;
        let expected = request.expected_head().content_id();
        let current = self.refs.read_ref(&campaign_ref)?;
        if current != Some(expected) {
            return Err(CampaignRepositoryError::RefConflict { current });
        }

        let mut translator = CampaignMigration::new(self, request.budget());
        translator.preflight_input(expected)?;
        let new_head = translator.translate_ancestry(expected)?;
        translator.charge_output_closure(new_head)?;
        self.validate_complete_head(new_head)?;

        match self
            .refs
            .compare_exchange(&campaign_ref, Some(expected), new_head)?
        {
            RefCasOutcome::Advanced { .. } => Ok(CampaignMigrationResult {
                prior_head: request.expected_head(),
                new_head: CampaignSnapshotId::from_content_id(new_head)?,
                input_objects: translator.charge.input_objects,
                input_bytes: translator.charge.input_bytes,
                output_objects: translator.charge.output_objects,
                output_bytes: translator.charge.output_bytes,
                mapped_entries: translator.charge.mapped_entries,
                ancestry: translator.charge.ancestry,
            }),
            RefCasOutcome::Conflict { current, .. } => {
                Err(CampaignRepositoryError::RefConflict { current })
            }
        }
    }
}

struct CampaignMigration<'a> {
    repository: &'a CampaignRepository,
    budget: CampaignMigrationBudget,
    charge: MigrationCharge,
    input: BTreeMap<ContentId, ObjectEnvelope>,
    translated: BTreeMap<ContentId, ContentId>,
    translating: BTreeSet<ContentId>,
}

impl<'a> CampaignMigration<'a> {
    fn new(repository: &'a CampaignRepository, budget: CampaignMigrationBudget) -> Self {
        Self {
            repository,
            budget,
            charge: MigrationCharge::default(),
            input: BTreeMap::new(),
            translated: BTreeMap::new(),
            translating: BTreeSet::new(),
        }
    }

    fn preflight_input(&mut self, head: ContentId) -> Result<(), CampaignRepositoryError> {
        let mut pending = vec![head];
        while let Some(id) = pending.pop() {
            if self.input.contains_key(&id) {
                continue;
            }
            let bytes = self.read_bytes(id)?;
            self.charge.input_objects = self.charge.input_objects.checked_add(1).ok_or(
                CampaignRepositoryError::MigrationBudgetExceeded {
                    limit: CampaignMigrationLimit::InputObjects,
                },
            )?;
            if self.charge.input_objects > self.budget.maximum_objects {
                return Err(CampaignRepositoryError::MigrationBudgetExceeded {
                    limit: CampaignMigrationLimit::InputObjects,
                });
            }
            self.charge.input_bytes = self.charge_bytes(
                self.charge.input_bytes,
                bytes.len(),
                self.budget.maximum_input_bytes,
                CampaignMigrationLimit::InputBytes,
            )?;
            let envelope = self.decode_migration_envelope(id, &bytes)?;
            if envelope.record_kind() == crate::CampaignRecordKind::MeasurementSet
                && envelope.schema_version() == 1
            {
                return Err(integrity(
                    "legacy-measurement-set-has-no-verifiable-evaluation",
                ));
            }
            if envelope.record_kind() == crate::CampaignRecordKind::ScenarioArtifact {
                let artifact = crate::ScenarioArtifact::from_canonical_bytes(envelope.body())?;
                if obsolete_execution_model_payload(artifact.payload()) {
                    return Err(integrity("obsolete-scenario-payload-is-not-migratable"));
                }
            }
            if envelope.record_kind() == crate::CampaignRecordKind::ReproductionArtifact {
                let artifact = crate::ReproductionArtifact::from_canonical_bytes(envelope.body())?;
                if obsolete_execution_model_payload(artifact.payload()) {
                    return Err(integrity("obsolete-reproduction-payload-is-not-migratable"));
                }
            }
            if envelope.record_kind() == crate::CampaignRecordKind::PlannerEngine {
                let engine: crate::PlannerEngine = codec::decode(envelope.body())?;
                let packaged = matches!(
                    engine.name(),
                    "crucible-canonical-frontier"
                        | "crucible-canonical-beam"
                        | "crucible-canonical-search-order"
                );
                let current = crate::CanonicalFrontierPlanner::supports_descriptor(&engine)?
                    || crate::CanonicalPuctPlanner::supports_descriptor(&engine)?
                    || crate::CanonicalBeamPlanner::supports_descriptor(&engine)?
                    || crate::CanonicalSearchPlanner::supports_descriptor(&engine)?;
                if packaged && !current {
                    return Err(integrity(
                        "obsolete-packaged-planner-engine-is-not-migratable",
                    ));
                }
            }
            pending.extend(envelope.children().iter().map(|child| child.id()));
            self.input.insert(id, envelope);
        }
        Ok(())
    }

    fn translate_ancestry(
        &mut self,
        head: ContentId,
    ) -> Result<ContentId, CampaignRepositoryError> {
        let mut ancestry = Vec::new();
        let mut cursor = Some(head);
        while let Some(id) = cursor {
            self.charge.ancestry = self.charge.ancestry.checked_add(1).ok_or(
                CampaignRepositoryError::MigrationBudgetExceeded {
                    limit: CampaignMigrationLimit::Ancestry,
                },
            )?;
            if self.charge.ancestry > self.budget.maximum_ancestry {
                return Err(CampaignRepositoryError::MigrationBudgetExceeded {
                    limit: CampaignMigrationLimit::Ancestry,
                });
            }
            let snapshot = self.decode_legacy_snapshot(id)?;
            cursor = snapshot.parent.map(CampaignMigrationHead::content_id);
            ancestry.push((id, snapshot));
        }

        for (old_id, snapshot) in ancestry.into_iter().rev() {
            let roots = self.translate_roots(snapshot.roots)?;
            let ledger = self.build_ledger(snapshot.roots, roots.accounting)?;
            let ledger_id = self.repository.put_budget_ledger(ledger)?;
            let current = match (snapshot.parent, snapshot.transition) {
                (None, None) => CampaignSnapshot::genesis(
                    snapshot.lineage,
                    snapshot.active_policy,
                    roots,
                    ledger_id,
                )?,
                (Some(parent), Some(transition)) => {
                    let parent = CampaignSnapshotId::from_content_id(
                        self.required_mapping(parent.content_id())?,
                    )?;
                    let transition = CampaignFactId::from_content_id(
                        self.translate_fact(transition.content_id())?,
                    )?;
                    CampaignSnapshot::successor(
                        parent,
                        snapshot.lineage,
                        snapshot.active_policy,
                        roots,
                        transition,
                        ledger_id,
                    )?
                }
                _ => return Err(integrity("legacy-snapshot-parent-transition-disagree")),
            };
            let new_id = self.repository.put_snapshot(&current)?;
            self.translated.insert(old_id, new_id);
        }
        self.required_mapping(head)
    }

    fn translate_roots(
        &mut self,
        roots: CampaignRoots,
    ) -> Result<CampaignRoots, CampaignRepositoryError> {
        Ok(CampaignRoots {
            graph: self.translate_map(roots.graph)?,
            exploration: self.translate_map(roots.exploration)?,
            observations: self.translate_map(roots.observations)?,
            corpus: self.translate_map(roots.corpus)?,
            coverage: self.translate_map(roots.coverage)?,
            findings: self.translate_map(roots.findings)?,
            pins: self.translate_map(roots.pins)?,
            accounting: self.translate_map(roots.accounting)?,
            coordination: self.translate_map(roots.coordination)?,
        })
    }

    fn translate_map(&mut self, old_root: ContentId) -> Result<ContentId, CampaignRepositoryError> {
        if let Some(mapped) = self.translated.get(&old_root) {
            return Ok(*mapped);
        }
        let mut root = self.repository.merkle.empty()?.content_id();
        let mut after = None;
        loop {
            let page = self
                .repository
                .merkle
                .scan(old_root, after, MIGRATION_MAP_PAGE_ITEMS)?;
            for (old_key, old_value) in page.entries() {
                self.charge_map_entries(1)?;
                let new_value = self.translate_object(*old_value)?;
                let new_key = migrated_map_key(*old_key, *old_value, new_value);
                root = self
                    .repository
                    .merkle
                    .insert(root, new_key, new_value)?
                    .content_id();
            }
            let Some(next) = page.next_after() else {
                break;
            };
            after = Some(next);
        }
        self.translated.insert(old_root, root);
        Ok(root)
    }

    fn translate_object(&mut self, old: ContentId) -> Result<ContentId, CampaignRepositoryError> {
        if let Some(mapped) = self.translated.get(&old) {
            return Ok(*mapped);
        }
        if !self.translating.insert(old) {
            return Err(integrity("legacy-campaign-object-cycle"));
        }
        let envelope = self
            .input
            .get(&old)
            .cloned()
            .ok_or_else(|| integrity("migration-input-object-was-not-preflighted"))?;
        let new = match (envelope.record_kind(), envelope.schema_version()) {
            (crate::CampaignRecordKind::AttemptAdmission, 1..=2) => {
                self.translate_admission(old, &envelope)?
            }
            (crate::CampaignRecordKind::Fact, _) => self.translate_fact(old)?,
            (crate::CampaignRecordKind::MerkleNode, _) => self.translate_map(old)?,
            (crate::CampaignRecordKind::Snapshot, _) => self.required_mapping(old)?,
            (crate::CampaignRecordKind::BudgetLedger, 1) => {
                return Err(integrity("orphan-legacy-budget-ledger-is-not-migratable"));
            }
            (crate::CampaignRecordKind::MeasurementSet, 1) => {
                return Err(integrity(
                    "legacy-measurement-set-has-no-verifiable-evaluation",
                ));
            }
            (crate::CampaignRecordKind::BranchRequest, 1) => {
                return Err(integrity(
                    "obsolete-branch-request-has-no-current-translation",
                ));
            }
            (crate::CampaignRecordKind::BranchPath, 1)
            | (crate::CampaignRecordKind::PlannerStep, 3)
            | (crate::CampaignRecordKind::Finding, 1 | 3)
            | (crate::CampaignRecordKind::PlannerCandidateBudget, 1)
            | (crate::CampaignRecordKind::PlannerCandidateGuidance, 1) => {
                return Err(integrity(
                    "obsolete-campaign-record-has-no-current-translation",
                ));
            }
            _ => {
                for child in envelope.children() {
                    if self.translate_object(child.id())? != child.id() {
                        return Err(integrity("legacy-reference-rewrite-is-unsupported"));
                    }
                }
                old
            }
        };
        self.translating.remove(&old);
        self.translated.insert(old, new);
        Ok(new)
    }

    fn translate_admission(
        &mut self,
        old: ContentId,
        envelope: &ObjectEnvelope,
    ) -> Result<ContentId, CampaignRepositoryError> {
        let legacy: LegacyAttemptAdmission = codec::decode(envelope.body())?;
        legacy.validate_envelope(envelope)?;
        let policy = match legacy.role {
            AttemptAdmissionRole::ExecutionBasis {
                proposal: Some(proposal),
                ..
            }
            | AttemptAdmissionRole::AdditionalCause { proposal } => self
                .repository
                .read_proposal(proposal.content_id())?
                .policy(),
            AttemptAdmissionRole::ExecutionBasis {
                cause:
                    BranchRequestCause::ExhaustivePolicy(policy)
                    | BranchRequestCause::ScenarioDefault(policy),
                ..
            } => policy,
            AttemptAdmissionRole::ExecutionBasis { proposal: None, .. } => {
                return Err(integrity(
                    "legacy-attempt-admission-policy-is-not-derivable",
                ));
            }
        };
        let admission = AttemptAdmission::new(legacy.attempt, legacy.role, policy);
        let new = self.repository.put_attempt_admission(&admission)?;
        self.translated.insert(old, new);
        Ok(new)
    }

    fn translate_fact(&mut self, old: ContentId) -> Result<ContentId, CampaignRepositoryError> {
        if let Some(mapped) = self.translated.get(&old) {
            return Ok(*mapped);
        }
        let envelope = self
            .input
            .get(&old)
            .ok_or_else(|| integrity("migration-fact-was-not-preflighted"))?;
        if envelope.schema_version() == 2 {
            if let Ok(legacy) = codec::decode::<LegacyAttemptAdmissionFact>(envelope.body()) {
                legacy.validate_envelope(envelope)?;
                let admission =
                    AttemptAdmissionId::from_content_id(self.translate_object(legacy.admission)?)?;
                let new = self
                    .repository
                    .put_fact(&CampaignFact::AttemptAdmitted(admission))?;
                self.translated.insert(old, new);
                return Ok(new);
            }
        }

        let fact = CampaignFact::from_canonical_bytes(envelope.body())?;
        if ObjectEnvelope::for_fact(&fact)?.children() != envelope.children() {
            return Err(integrity("migration-fact-child-table-mismatch"));
        }
        let new = self.repository.put_fact(&fact)?;
        self.translated.insert(old, new);
        Ok(new)
    }

    fn build_ledger(
        &mut self,
        old_roots: CampaignRoots,
        new_accounting: ContentId,
    ) -> Result<CampaignBudgetLedger, CampaignRepositoryError> {
        let mut grants = (0_u128, 0_u128);
        self.scan_map(old_roots.accounting, |this, key, content| {
            let envelope = this
                .input
                .get(&content)
                .ok_or_else(|| integrity("migration-accounting-value-was-not-preflighted"))?;
            if envelope.record_kind() != crate::CampaignRecordKind::Fact {
                return Ok(());
            }
            let CampaignFact::ControlRequested(request) =
                CampaignFact::from_canonical_bytes(envelope.body())?
            else {
                return Ok(());
            };
            if key == map_key_hash("accounting.command", request.command.as_hash())
                && let CampaignControlAction::GrantBudget(grant) = request.action
            {
                grants.0 = grants
                    .0
                    .checked_add(u128::from(grant.proposals()))
                    .ok_or_else(|| integrity("migration-budget-grant-overflow"))?;
                grants.1 = grants
                    .1
                    .checked_add(u128::from(grant.attempts()))
                    .ok_or_else(|| integrity("migration-budget-grant-overflow"))?;
            }
            Ok(())
        })?;
        let mut proposals = 0_u64;
        self.scan_map(old_roots.exploration, |this, key, content| {
            if key == proposal_content_key(content) {
                this.repository.read_proposal(content)?;
                proposals = proposals
                    .checked_add(1)
                    .ok_or_else(|| integrity("migration-proposal-count-overflow"))?;
            }
            Ok(())
        })?;
        let attempts = self.repository.accounted_attempts(new_accounting)?;
        self.charge_map_entries(usize::try_from(attempts).map_err(|_| {
            CampaignRepositoryError::MigrationBudgetExceeded {
                limit: CampaignMigrationLimit::MapEntries,
            }
        })?)?;
        let request_spending = self.build_request_spending(new_accounting)?;
        Ok(CampaignBudgetLedger::from_accounted_totals(
            grants.0,
            grants.1,
            proposals,
            attempts,
            request_spending,
        )?)
    }

    fn build_request_spending(
        &mut self,
        accounting: ContentId,
    ) -> Result<ContentId, CampaignRepositoryError> {
        let empty = self.repository.merkle.empty()?.content_id();
        let seed = CampaignBudgetLedger::from_accounted_totals(0, 0, 0, 0, empty)?;
        self.repository
            .request_spending_root_after(seed, accounting, true)
    }

    fn scan_map(
        &mut self,
        root: ContentId,
        mut visit: impl FnMut(&mut Self, CampaignHash, ContentId) -> Result<(), CampaignRepositoryError>,
    ) -> Result<(), CampaignRepositoryError> {
        let mut after = None;
        loop {
            let page = self
                .repository
                .merkle
                .scan(root, after, MIGRATION_MAP_PAGE_ITEMS)?;
            for (key, value) in page.entries() {
                self.charge_map_entries(1)?;
                visit(self, *key, *value)?;
            }
            let Some(next) = page.next_after() else {
                return Ok(());
            };
            after = Some(next);
        }
    }

    fn decode_legacy_snapshot(
        &self,
        id: ContentId,
    ) -> Result<LegacyCampaignSnapshot, CampaignRepositoryError> {
        if id.kind() != ObjectKind::CampaignSnapshot {
            return Err(integrity("migration-snapshot-content-kind"));
        }
        let envelope = self
            .input
            .get(&id)
            .ok_or_else(|| integrity("migration-snapshot-was-not-preflighted"))?;
        if envelope.record_kind() != crate::CampaignRecordKind::Snapshot
            || envelope.schema_version() != 2
        {
            return Err(integrity("campaign-head-does-not-require-legacy-migration"));
        }
        let snapshot: LegacyCampaignSnapshot = codec::decode(envelope.body())?;
        snapshot.validate_envelope(envelope)?;
        Ok(snapshot)
    }

    fn charge_output_closure(&mut self, head: ContentId) -> Result<(), CampaignRepositoryError> {
        let mut visited = BTreeSet::new();
        let mut pending = vec![head];
        while let Some(id) = pending.pop() {
            if !visited.insert(id) {
                continue;
            }
            let bytes = self.read_bytes(id)?;
            self.charge.output_objects = self.charge.output_objects.checked_add(1).ok_or(
                CampaignRepositoryError::MigrationBudgetExceeded {
                    limit: CampaignMigrationLimit::OutputObjects,
                },
            )?;
            if self.charge.output_objects > self.budget.maximum_objects {
                return Err(CampaignRepositoryError::MigrationBudgetExceeded {
                    limit: CampaignMigrationLimit::OutputObjects,
                });
            }
            self.charge.output_bytes = self.charge_bytes(
                self.charge.output_bytes,
                bytes.len(),
                self.budget.maximum_output_bytes,
                CampaignMigrationLimit::OutputBytes,
            )?;
            let envelope = if id.kind() == ObjectKind::MerkleNode {
                ObjectEnvelope::from_canonical_bytes_for_owner(&bytes)?
            } else {
                ObjectEnvelope::from_canonical_bytes(&bytes)?
            };
            pending.extend(envelope.children().iter().map(|child| child.id()));
        }
        Ok(())
    }

    fn decode_migration_envelope(
        &self,
        id: ContentId,
        bytes: &[u8],
    ) -> Result<ObjectEnvelope, CampaignRepositoryError> {
        let envelope = if id.kind() == ObjectKind::MerkleNode {
            ObjectEnvelope::from_canonical_bytes_for_owner(bytes)?
        } else {
            crate::object::migration::decode_historical_envelope(bytes)?
        };
        if envelope.content_id() != id {
            return Err(integrity("migration-envelope-content-id-mismatch"));
        }
        Ok(envelope)
    }

    fn read_bytes(&self, id: ContentId) -> Result<Vec<u8>, CampaignRepositoryError> {
        let handle = self.repository.blobs.read(id, None)?;
        if handle.logical_length() > self.budget.maximum_object_bytes {
            return Err(CampaignRepositoryError::MigrationBudgetExceeded {
                limit: CampaignMigrationLimit::ObjectBytes,
            });
        }
        Ok(handle.read_all(self.budget.maximum_object_bytes)?)
    }

    fn charge_bytes(
        &self,
        prior: u64,
        bytes: usize,
        maximum: u64,
        limit: CampaignMigrationLimit,
    ) -> Result<u64, CampaignRepositoryError> {
        let total = prior
            .checked_add(bytes as u64)
            .ok_or(CampaignRepositoryError::MigrationBudgetExceeded { limit })?;
        if total > maximum {
            return Err(CampaignRepositoryError::MigrationBudgetExceeded { limit });
        }
        Ok(total)
    }

    fn charge_map_entries(&mut self, entries: usize) -> Result<(), CampaignRepositoryError> {
        self.charge.mapped_entries = self.charge.mapped_entries.checked_add(entries).ok_or(
            CampaignRepositoryError::MigrationBudgetExceeded {
                limit: CampaignMigrationLimit::MapEntries,
            },
        )?;
        if self.charge.mapped_entries > self.budget.maximum_objects {
            return Err(CampaignRepositoryError::MigrationBudgetExceeded {
                limit: CampaignMigrationLimit::MapEntries,
            });
        }
        Ok(())
    }

    fn required_mapping(&self, old: ContentId) -> Result<ContentId, CampaignRepositoryError> {
        self.translated
            .get(&old)
            .copied()
            .ok_or_else(|| integrity("migration-required-identity-is-not-translated"))
    }
}

fn proposal_content_key(content: ContentId) -> CampaignHash {
    map_key_content("exploration.proposal", content)
}

fn obsolete_execution_model_payload(payload: &[u8]) -> bool {
    [
        b"crucible.scenario-def-form.v5\0".as_slice(),
        b"crucible.scenario-def-form.v6\0".as_slice(),
        b"crucible.reproduction-artifact.v5\0".as_slice(),
        b"crucible.reproduction-artifact.v6\0".as_slice(),
    ]
    .into_iter()
    .any(|magic| payload.starts_with(magic))
}

fn migrated_map_key(old_key: CampaignHash, old: ContentId, new: ContentId) -> CampaignHash {
    if old != new && old_key == map_key_content("accounting.attempt-admission", old) {
        map_key_content("accounting.attempt-admission", new)
    } else {
        old_key
    }
}
