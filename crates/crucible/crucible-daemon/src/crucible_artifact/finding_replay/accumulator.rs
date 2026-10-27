//! Deduplicated replay-record accumulation, retained-record access, and
//! validation.
//!
//! Each newly seen record is written to the transcript's
//! [`ReplayRecordStore`] as it arrives. Memory keeps only the identity set, the
//! per-kind identity tables in first-seen order, and the aggregate byte
//! charge, so retained replay evidence occupies the store, not the process.

use super::*;
use crate::{ReplayRecord, ReplayRecordError, ReplayRecordStore};

/// Typed identities of retained records, one table per record kind.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::crucible_artifact) struct ReplayRecordIds {
    pub(in crate::crucible_artifact) configurations: Vec<ConfigurationArtifactId>,
    pub(in crate::crucible_artifact) measurements: Vec<MeasurementSetId>,
    pub(in crate::crucible_artifact) properties: Vec<PropertyVerdictSetId>,
    pub(in crate::crucible_artifact) coverage: Vec<CoverageProjectionId>,
    pub(in crate::crucible_artifact) declarations: Vec<SelectableId>,
    pub(in crate::crucible_artifact) domains: Vec<ChoiceDomainId>,
    pub(in crate::crucible_artifact) opportunities: Vec<ChoiceOpportunityId>,
    pub(in crate::crucible_artifact) selections: Vec<SelectionId>,
}

impl ReplayRecordIds {
    pub(in crate::crucible_artifact) const fn new() -> Self {
        Self {
            configurations: Vec::new(),
            measurements: Vec::new(),
            properties: Vec::new(),
            coverage: Vec::new(),
            declarations: Vec::new(),
            domains: Vec::new(),
            opportunities: Vec::new(),
            selections: Vec::new(),
        }
    }

    /// Returns every identity in canonical table order.
    pub(in crate::crucible_artifact) fn content_ids(&self) -> impl Iterator<Item = ContentId> + '_ {
        self.configurations
            .iter()
            .map(|id| id.content_id())
            .chain(self.measurements.iter().map(|id| id.content_id()))
            .chain(self.properties.iter().map(|id| id.content_id()))
            .chain(self.coverage.iter().map(|id| id.content_id()))
            .chain(self.declarations.iter().map(|id| id.content_id()))
            .chain(self.domains.iter().map(|id| id.content_id()))
            .chain(self.opportunities.iter().map(|id| id.content_id()))
            .chain(self.selections.iter().map(|id| id.content_id()))
    }

    fn append(&mut self, other: Self) {
        self.configurations.extend(other.configurations);
        self.measurements.extend(other.measurements);
        self.properties.extend(other.properties);
        self.coverage.extend(other.coverage);
        self.declarations.extend(other.declarations);
        self.domains.extend(other.domains);
        self.opportunities.extend(other.opportunities);
        self.selections.extend(other.selections);
    }
}

/// The distinct records both replay passes retain, by identity.
///
/// The record bytes stay in the stores behind [`Self::sources`]; every read
/// authenticates the record against its identity. Equality compares the
/// identities and charges, never the store handles.
#[derive(Clone, Debug)]
pub(in crate::crucible_artifact) struct PreparedFindingReplayRecords {
    pub(in crate::crucible_artifact) ids: ReplayRecordIds,
    pub(in crate::crucible_artifact) sources: crate::ReplayRecordSources,
    pub(in crate::crucible_artifact) record_count: usize,
    pub(in crate::crucible_artifact) canonical_bytes: u64,
}

impl PartialEq for PreparedFindingReplayRecords {
    fn eq(&self, other: &Self) -> bool {
        self.ids == other.ids
            && self.record_count == other.record_count
            && self.canonical_bytes == other.canonical_bytes
    }
}

impl Eq for PreparedFindingReplayRecords {}

impl PreparedFindingReplayRecords {
    /// Reads and authenticates one retained record.
    pub(in crate::crucible_artifact) fn load<T: crate::ReplayRecord>(
        &self,
        id: T::Id,
    ) -> Result<T, crate::ReplayRecordError> {
        crate::load_replay_record::<T>(&self.sources, id).map(|(record, _)| record)
    }

    /// Visits every retained record of one kind in table order.
    ///
    /// Records are read and authenticated one at a time.
    pub(in crate::crucible_artifact) fn try_for_each<T, E>(
        &self,
        ids: &[T::Id],
        mut visit: impl FnMut(&T) -> Result<(), E>,
    ) -> Result<(), E>
    where
        T: crate::ReplayRecord,
        E: From<crate::ReplayRecordError>,
    {
        for id in ids {
            visit(&self.load::<T>(*id)?)?;
        }
        Ok(())
    }

    /// Retains one more record, held in a new memory store, for tests that
    /// tamper with a prepared closure.
    #[cfg(test)]
    pub(in crate::crucible_artifact) fn insert_for_test<T: crate::ReplayRecord>(
        &mut self,
        record: &T,
        table: impl FnOnce(&mut ReplayRecordIds) -> &mut Vec<T::Id>,
    ) -> T::Id {
        let id = record
            .record_id()
            .unwrap_or_else(|error| panic!("test record identity: {error}"));
        let mut store = crate::ReplayRecordStore::memory();
        store
            .put(T::content_id(id), &record.encode())
            .unwrap_or_else(|error| panic!("test record write: {error}"));
        self.sources.extend(store.sources());
        table(&mut self.ids).push(id);
        id
    }

    /// Visits every retained record's canonical bytes in table order.
    ///
    /// Each record is read and authenticated before it is visited.
    pub(in crate::crucible_artifact) fn try_for_each_encoded<E>(
        &self,
        mut visit: impl FnMut(ContentId, &[u8]) -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<crate::ReplayRecordError>,
    {
        fn table<T: crate::ReplayRecord, E: From<crate::ReplayRecordError>>(
            records: &PreparedFindingReplayRecords,
            ids: &[T::Id],
            visit: &mut impl FnMut(ContentId, &[u8]) -> Result<(), E>,
        ) -> Result<(), E> {
            for id in ids {
                let record = records.load::<T>(*id)?;
                visit(T::content_id(*id), &record.encode())?;
            }
            Ok(())
        }

        let ids = &self.ids;
        table::<ConfigurationArtifact, E>(self, &ids.configurations, &mut visit)?;
        table::<MeasurementSet, E>(self, &ids.measurements, &mut visit)?;
        table::<PropertyVerdictSet, E>(self, &ids.properties, &mut visit)?;
        table::<CoverageProjection, E>(self, &ids.coverage, &mut visit)?;
        table::<SelectableDeclaration, E>(self, &ids.declarations, &mut visit)?;
        table::<ChoiceDomain, E>(self, &ids.domains, &mut visit)?;
        table::<ChoiceOpportunity, E>(self, &ids.opportunities, &mut visit)?;
        table::<Selection, E>(self, &ids.selections, &mut visit)
    }
}

/// The records one replay adds, prepared before any of them is admitted.
#[derive(Default)]
struct PendingRecords {
    ids: ReplayRecordIds,
    writes: Vec<(ContentId, Vec<u8>)>,
    seen: BTreeSet<ContentId>,
    bytes: u64,
}

impl PendingRecords {
    /// Stages `record` unless it is already retained or staged.
    fn stage<T: ReplayRecord>(
        &mut self,
        retained: &BTreeSet<ContentId>,
        record: &T,
        table: impl FnOnce(&mut ReplayRecordIds) -> &mut Vec<T::Id>,
    ) -> Result<T::Id, CrucibleArtifactError> {
        let id = record.record_id()?;
        let content = T::content_id(id);
        if retained.contains(&content) || !self.seen.insert(content) {
            return Ok(id);
        }

        let bytes = record.encode();
        self.bytes = self.bytes.saturating_add(bytes.len() as u64);
        self.writes.push((content, bytes));
        table(&mut self.ids).push(id);
        Ok(id)
    }
}

#[derive(Clone, Debug)]
pub(in crate::crucible_artifact) struct ReplayRecordAccumulator {
    pub(super) ids: BTreeSet<ContentId>,
    tables: ReplayRecordIds,
    store: ReplayRecordStore,
    pub(super) canonical_bytes: u64,
}

/// Records are content-addressed, so equal identities name equal records
/// wherever the store keeps them.
impl PartialEq for ReplayRecordAccumulator {
    fn eq(&self, other: &Self) -> bool {
        self.ids == other.ids
            && self.tables == other.tables
            && self.canonical_bytes == other.canonical_bytes
    }
}

impl Eq for ReplayRecordAccumulator {}

impl Default for ReplayRecordAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayRecordAccumulator {
    pub(super) const fn new() -> Self {
        Self::with_store(ReplayRecordStore::memory())
    }

    pub(super) const fn with_store(store: ReplayRecordStore) -> Self {
        Self {
            ids: BTreeSet::new(),
            tables: ReplayRecordIds::new(),
            store,
            canonical_bytes: 0,
        }
    }

    pub(super) fn record_outcome(
        &mut self,
        candidate: &FindingReproductionArtifact,
        replay: AutomaticFindingReplayOutcome,
    ) -> Result<RecordedFindingReplay, CrucibleArtifactError> {
        match replay {
            AutomaticFindingReplayOutcome::Observed { evidence, .. } => {
                validate_replay_configuration(candidate, &evidence)?;
                self.record_observed(*evidence)
            }
            AutomaticFindingReplayOutcome::DeterministicallyIncompatible {
                configuration,
                reason,
            } => {
                validate_incompatible_configuration(candidate, &configuration)?;
                let mut pending = PendingRecords::default();
                let configuration = pending.stage(&self.ids, &configuration, |tables| {
                    &mut tables.configurations
                })?;
                self.admit(pending, 0)?;
                Ok(RecordedFindingReplay::DeterministicallyIncompatible {
                    configuration,
                    reason,
                })
            }
        }
    }

    pub(super) fn record_observed(
        &mut self,
        replay: CrucibleFindingReplayEvidence,
    ) -> Result<RecordedFindingReplay, CrucibleArtifactError> {
        replay.validate_signature_ownership()?;

        let mut pending = PendingRecords::default();
        let configuration = pending.stage(&self.ids, &replay.configuration, |tables| {
            &mut tables.configurations
        })?;
        let measurements = pending.stage(&self.ids, &replay.measurements, |tables| {
            &mut tables.measurements
        })?;
        let properties = pending.stage(&self.ids, &replay.properties, |tables| {
            &mut tables.properties
        })?;
        let coverage = pending.stage(&self.ids, &replay.coverage, |tables| &mut tables.coverage)?;
        for declaration in &replay.declarations {
            pending.stage(&self.ids, declaration, |tables| &mut tables.declarations)?;
        }
        for domain in &replay.domains {
            pending.stage(&self.ids, domain, |tables| &mut tables.domains)?;
        }
        let opportunities = replay
            .opportunities
            .iter()
            .map(|opportunity| {
                pending.stage(&self.ids, opportunity, |tables| &mut tables.opportunities)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let selections = replay
            .selections
            .iter()
            .map(|selection| pending.stage(&self.ids, selection, |tables| &mut tables.selections))
            .collect::<Result<Vec<_>, _>>()?;

        let signature_bytes = replay
            .signature
            .as_ref()
            .map_or(0, |signature| signature.canonical_bytes().len() as u64);
        self.admit(pending, signature_bytes)?;
        Ok(RecordedFindingReplay::Observed {
            signature: replay.signature.map(Box::new),
            configuration,
            measurements,
            properties,
            coverage,
            opportunities,
            selections,
        })
    }

    /// Charges, writes, and then retains one replay's new records.
    ///
    /// Admission is atomic: a refused or failed replay leaves the retained
    /// identities and charges unchanged. Records written before a later write
    /// fails stay in the store unreferenced, and an identical retry rewrites
    /// them idempotently.
    fn admit(
        &mut self,
        pending: PendingRecords,
        signature_bytes: u64,
    ) -> Result<(), CrucibleArtifactError> {
        let count = self.ids.len().saturating_add(pending.writes.len());
        if count > MAX_CRUCIBLE_FINDING_REPLAY_RECORDS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-replay-retained-record-count",
            }
            .into());
        }
        let bytes = self
            .canonical_bytes
            .saturating_add(pending.bytes)
            .saturating_add(signature_bytes);
        if bytes > MAX_CRUCIBLE_FINDING_REPLAY_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-replay-retained-record-bytes",
            }
            .into());
        }

        for (record, bytes) in &pending.writes {
            self.store
                .put(*record, bytes)
                .map_err(|source| ReplayRecordError::Unwritable {
                    record: *record,
                    source,
                })?;
        }
        self.ids
            .extend(pending.writes.iter().map(|(record, _)| *record));
        self.tables.append(pending.ids);
        self.canonical_bytes = bytes;
        Ok(())
    }

    pub(in crate::crucible_artifact) fn finish(self) -> PreparedFindingReplayRecords {
        PreparedFindingReplayRecords {
            sources: self.store.sources(),
            ids: self.tables,
            record_count: self.ids.len(),
            canonical_bytes: self.canonical_bytes,
        }
    }
}

pub(super) fn validate_replay_configuration(
    candidate: &FindingReproductionArtifact,
    replay: &CrucibleFindingReplayEvidence,
) -> Result<(), CrucibleArtifactError> {
    let scenario = candidate.artifact.scenario_form();
    let scenario_artifact = encode_crucible_scenario_artifact(scenario)?;
    let expected =
        encode_crucible_configuration_artifact(&scenario_artifact, candidate.artifact.schedule())?;
    if replay.configuration != expected {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "finding replay candidate configuration",
        });
    }
    validate_owned_replay_selections(candidate, replay)?;
    replay.validate_signature_ownership()
}

pub(super) fn validate_incompatible_configuration(
    candidate: &FindingReproductionArtifact,
    replay: &ConfigurationArtifact,
) -> Result<(), CrucibleArtifactError> {
    let scenario = candidate.artifact.scenario_form();
    let scenario_artifact = encode_crucible_scenario_artifact(scenario)?;
    let expected =
        encode_crucible_configuration_artifact(&scenario_artifact, candidate.artifact.schedule())?;
    if replay != &expected {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "finding incompatible replay candidate configuration",
        });
    }
    Ok(())
}

pub(super) fn validate_owned_replay_selections(
    candidate: &FindingReproductionArtifact,
    replay: &CrucibleFindingReplayEvidence,
) -> Result<(), CrucibleArtifactError> {
    let declarations = replay
        .declarations
        .iter()
        .map(|value| value.id().map(|id| (id, value)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let domains = replay
        .domains
        .iter()
        .map(|value| value.id().map(|id| (id, value)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let mut choices = BTreeMap::new();
    for opportunity in &replay.opportunities {
        let declaration = declarations.get(&opportunity.declaration()).ok_or(
            CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "finding replay choice declaration",
            },
        )?;
        let domain = domains.get(&opportunity.domain()).ok_or(
            CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "finding replay choice domain",
            },
        )?;
        opportunity.validate_references(declaration, domain)?;
        if opportunity.scenario() != replay.configuration.scenario() {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "finding replay choice scenario",
            });
        }
        choices.insert(opportunity.id()?, (opportunity, declaration, domain));
    }

    let selections = replay
        .selections
        .iter()
        .map(|selection| selection.id().map(|id| (id, selection)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let mut embedded = BTreeSet::new();
    let mut covered_signal_fault_overrides = BTreeSet::new();
    let configuration = Configuration {
        def: candidate.artifact.scenario_def().clone(),
        schedule: candidate.artifact.schedule().clone(),
    };
    // Campaign-branch parents are identified prefixes of this one
    // configuration, so authenticating them copies no schedule.
    for (index, decision) in configuration.schedule.decision_history().iter().enumerate() {
        let Decision::Selection(decision) = decision else {
            continue;
        };
        let decoded = decision.selection()?;
        let id = decoded.id()?;
        let selection =
            selections
                .get(&id)
                .ok_or(CrucibleArtifactError::SemanticIdentityMismatch {
                    artifact: "finding replay embedded selection",
                })?;
        if **selection != decoded || !embedded.insert(id) {
            return Err(CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "finding replay embedded selection",
            });
        }
        let (opportunity, declaration, domain) = choices.get(&selection.opportunity()).ok_or(
            CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "finding replay selection opportunity",
            },
        )?;
        match selection.origin() {
            SelectionOrigin::Default | SelectionOrigin::LockedReplay => {
                selection.validate_replay(opportunity, domain)?;
            }
            SelectionOrigin::CampaignBranch { .. } => {
                let parent = ConfigurationPrefix::new(&configuration, index)?;
                selection.validate_branch_replay(
                    opportunity,
                    domain,
                    opportunity.branch_point_id(campaign_configuration_id(parent.id())),
                )?;
                if matches!(
                    opportunity.source(),
                    crucible_campaign::ChoiceSource::Environment { adapter, .. }
                        if adapter == crucible_engine::SIGNAL_FAULT_CAMPAIGN_ADAPTER
                ) {
                    let selectable = SignalFaultSelectable::from_records(
                        &parent,
                        declaration,
                        opportunity,
                        domain,
                    )?;
                    let branch = selectable.resolve_branch(selection)?;
                    if !super::super::configuration_codec::schedule_records_at(
                        &configuration,
                        index,
                        branch.decisions(),
                    ) {
                        return Err(CrucibleArtifactError::SignalFaultScheduleMismatch);
                    }
                    if branch.decisions().len() == 2 {
                        covered_signal_fault_overrides.insert(index + 1);
                    }
                }
            }
            SelectionOrigin::ModelSample(_) => {
                crucible_engine::validate_app_random_model_selection(
                    selection,
                    declaration,
                    opportunity,
                    domain,
                )
                .map_err(|_| CrucibleArtifactError::UnverifiedModelSelection)?;
            }
        }
    }
    if embedded.len() != selections.len() {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "finding replay selection set",
        });
    }
    if configuration
        .schedule
        .decision_history()
        .iter()
        .enumerate()
        .any(|(index, decision)| {
            matches!(decision, Decision::Override(override_decision)
                if override_decision.point.key.starts_with("signal-fault/")
                    && !covered_signal_fault_overrides.contains(&index))
        })
    {
        return Err(CrucibleArtifactError::UnboundSignalFaultOverride);
    }
    Ok(())
}

pub(crate) fn validate_recorded_replay_configuration(
    candidate: &FindingReproductionArtifact,
    replay: &RecordedFindingReplay,
) -> Result<(), CrucibleArtifactError> {
    let scenario = encode_crucible_scenario_artifact(candidate.artifact.scenario_form())?;
    let expected =
        encode_crucible_configuration_artifact(&scenario, candidate.artifact.schedule())?;
    if replay.configuration() != expected.id()? {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "finding replay candidate configuration",
        });
    }
    Ok(())
}
