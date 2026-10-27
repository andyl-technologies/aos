//! Durable, self-authenticating bytes for a prepared semantic attempt result.
//!
//! The result body retains the complete [`ObservationCandidate`], every raw
//! measurement replay leaf required by that observation or a finding replay,
//! and the optional prepared finding closure. Every member uses its strict
//! canonical bytes. Decoding reconstructs the aggregate values through their
//! checked constructors, so a journal cannot bypass observation-choice,
//! measurement-ownership, or finding-closure invariants.
//!
//! ```text
//! v11-magic
//! observation-child, measurements, properties, coverage
//! discovered-choice-count, discovered-choice records
//! produced-selection-count, selection records, observation, optional resolved-effect trace
//! measurement-replay-evidence-count, measurement-replay-evidence records
//! log-segment-count, encoded attempt-log segment records (identity order)
//! optional terminal-fingerprint records
//! finding-present
//! [discovery-path, minimization-seed, scenario, original configuration,
//!  original reproduction, minimized configuration, minimized reproduction,
//!  eight deduplicated replay record identity tables, two replay-index passes,
//!  four role-specific finding-triage replay records, finding bundle]
//! ```
//!
//! A reproduction names its schedule segments by identity, like the leaves'
//! log segments, and each triage replay record names the attempt-log segments
//! its payload references; the caller's segment stores yield them all when
//! the finding is decoded.
//!
//! Every record is a u32-length-prefixed canonical body. Counts and indexes are
//! u32 values. A replay record identity is a u8-length-prefixed canonical
//! content-identity string; the record bytes live in the result's record
//! sources (a journal's own copies once staged), and decoding reads and
//! authenticates each named record. Decoding caps the complete payload at
//! 1 GiB, each record at 64 MiB, and replay reconstruction by both reference
//! and referenced-byte budgets.
//!
//! Raw-leaf validation here proves structural ownership: exact trace identity,
//! a measurement evidence set of exactly the leaf and its log segments, and
//! scenario, configuration, and definition bindings. The result carries every
//! referenced segment, and only those, so it is a complete segment source for
//! its own leaves. It also authenticates an observation-stop proof against the owned
//! raw event prefix and terminal evidence. This codec does not possess
//! authenticated scenario measurement definitions and therefore does not
//! replay the leaf or compare the retained evaluation payload. Production
//! preparation and recovery must call
//! [`crate::verify_crucible_measurement_publication`] for the observation and
//! every finding replay before any child-first publication.

use std::collections::{BTreeMap, BTreeSet};

use crucible_campaign::{
    CampaignCodecError, ChoiceDiscovery, ChoiceDomain, ChoiceOpportunity, ConfigurationArtifact,
    CoverageProjection, FindingCandidateBundle, FindingKind, FindingSignature, FindingTarget,
    FindingTriageReplayEvidence, MeasurementSet, Observation, ObservationCandidate,
    PropertyVerdict, PropertyVerdictSet, ReproductionArtifact, ScenarioArtifact,
    SelectableDeclaration, Selection, StopOutcome,
};
use crucible_engine::{
    AssertionPhase, ContentHash, ExecutionFingerprint, FailureClusterReportFailure, FailureKind,
    FailureTriageReplayEvidence, FindingReproductionArtifact, FingerprintSample, NodeId,
    ObservableEventPayload, ScenarioDefForm, SchedulerEventLogEntry, SchedulerEventLogPayload,
    VirtualTime,
};
use thiserror::Error;

mod replay_records;
use replay_records::{
    Decoder, Encoder, ReplayMaterialTables, decode_record_ids, decode_replay_indexes,
    discovery_path_from_tag, discovery_path_tag, encode_record_ids, encode_replays,
    materialize_replays, validate_recorded_replays,
};

use super::finding_replay::{PreparedFindingReplayRecords, ReplayRecordIds};
use super::{
    CrucibleArtifactError, FindingReplayIncompatibility, MAX_CRUCIBLE_FINDING_REPLAY_BYTES,
    MAX_CRUCIBLE_FINDING_REPLAY_RECORDS, MAX_CRUCIBLE_FINDING_REPLAYS_PER_PASS,
    PreparedCrucibleFindingCandidate, PreparedFindingTriageReplayRecords, RecordedFindingReplay,
    prepare_minimized_reproduction, prepare_original_reproduction, replay_recorded_signature_pass,
};
use crate::{
    AttemptLogSegmentSource, AttemptLogSegmentSources,
    CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V3, CrucibleMeasurementError,
    CrucibleMeasurementReplayEvidence, ReplayRecordSources, measurement_replay_leaf_id,
    verify_crucible_measurement_publication,
};

const PREPARED_RESULT_MAGIC_V10: &[u8] =
    b"crucible.executor.prepared-semantic-attempt-result.v11\0";
pub(super) const MAX_PREPARED_RESULT_RECORDS: usize = 200_000;
const MAX_RECORD_BYTES: usize = 64 * 1024 * 1024;
const MAX_REPLAY_VALIDATION_REFERENCES: usize = 4 * 1024 * 1024;
// Every retained replay record is charged at least one validation reference.
const _: () = assert!(MAX_CRUCIBLE_FINDING_REPLAY_RECORDS <= MAX_REPLAY_VALIDATION_REFERENCES);

/// Maximum encoded bytes retained by one prepared semantic result journal.
pub const MAX_PREPARED_SEMANTIC_RESULT_BYTES: usize = 1024 * 1024 * 1024;

/// Complete immutable semantic result retained across publication retries.
///
/// The result references its attempt-log segments by identity through its
/// measurement leaves, and its resolved-effect trace segments through the
/// observation's trace reference. It holds only read handles to the stores
/// containing them, so neither its memory nor its encoding grows with the
/// attempt log or the trace.
/// Equality compares the recorded content, never the store handles.
#[derive(Clone, Debug)]
pub struct PreparedSemanticAttemptResult {
    observation: ObservationCandidate,
    measurement_replay_evidence: Vec<CrucibleMeasurementReplayEvidence>,
    log_segments: AttemptLogSegmentSources,
    terminal_fingerprints: Option<Vec<FingerprintSample>>,
    finding: Option<PreparedCrucibleFindingCandidate>,
}

impl PartialEq for PreparedSemanticAttemptResult {
    fn eq(&self, other: &Self) -> bool {
        // Segments are content-addressed and named by the leaves, so equal
        // leaves reference equal segments wherever their bytes are stored.
        self.observation == other.observation
            && self.measurement_replay_evidence == other.measurement_replay_evidence
            && self.terminal_fingerprints == other.terminal_fingerprints
            && self.finding == other.finding
    }
}

impl Eq for PreparedSemanticAttemptResult {}

impl PreparedSemanticAttemptResult {
    /// Binds an observation and finding to all required raw measurement leaves.
    ///
    /// The leaves are retained in content-identity order, and duplicates are
    /// rejected. The supplied set must exactly cover every Crucible measurement
    /// payload v2 referenced by the observation and both finding replay passes,
    /// and `log_segments` must yield every segment those leaves reference. The
    /// finding's reproduction schedule segments are served from its resident
    /// schedules. This authenticates closure ownership and any observation-stop proof;
    /// callers must separately run [`crate::verify_crucible_measurement_publication`]
    /// with the authenticated scenario definitions before publication.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedSemanticResultCodecError`] when a leaf is duplicated,
    /// unowned, absent, or bound to a different scenario, configuration, or
    /// measurement definition, when a referenced segment is absent or fails
    /// authentication, or when the finding does not belong to the observation.
    pub fn new(
        observation: ObservationCandidate,
        measurement_replay_evidence: Vec<CrucibleMeasurementReplayEvidence>,
        log_segments: impl Into<AttemptLogSegmentSources>,
        finding: Option<PreparedCrucibleFindingCandidate>,
    ) -> Result<Self, PreparedSemanticResultCodecError> {
        let mut log_segments = log_segments.into();
        // A journal stages the finding's schedule and triage log segments only
        // when it is created, so until then the resident schedules and the
        // replay stores serve them.
        if let Some(finding) = &finding {
            log_segments.push(std::sync::Arc::new(
                finding.resident_reproduction_segments()?,
            ));
            if let Some(triage_replays) = &finding.triage_replays {
                log_segments.extend(triage_replays.segments.clone());
            }
        }
        validate_measurement_evidence_order(&measurement_replay_evidence)?;
        validate_log_segments(&measurement_replay_evidence, &log_segments)?;
        validate_pair(&observation, finding.as_ref())?;
        validate_measurement_evidence(
            &observation,
            &measurement_replay_evidence,
            &log_segments,
            finding.as_ref(),
        )?;
        Ok(Self {
            observation,
            measurement_replay_evidence,
            log_segments,
            terminal_fingerprints: None,
            finding,
        })
    }

    /// Attaches the complete terminal fingerprint set captured after execution.
    ///
    /// Samples are retained in node-name order. The caller must separately use
    /// [`Self::verify_terminal_fingerprints`] with the authenticated scenario
    /// before publication.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedSemanticResultCodecError`] when the samples exceed the
    /// QEMU world bound, contain duplicate or out-of-order nodes, or terminal
    /// evidence was already attached.
    pub fn with_terminal_fingerprints(
        mut self,
        terminal_fingerprints: Vec<FingerprintSample>,
    ) -> Result<Self, PreparedSemanticResultCodecError> {
        if self.terminal_fingerprints.is_some() {
            return Err(inconsistent("duplicate terminal fingerprint attachment"));
        }
        validate_terminal_fingerprints(&terminal_fingerprints)?;
        self.terminal_fingerprints = Some(terminal_fingerprints);
        Ok(self)
    }

    /// Returns the complete canonical observation candidate.
    #[must_use]
    pub const fn observation(&self) -> &ObservationCandidate {
        &self.observation
    }

    /// Returns raw measurement leaves in content-identity order.
    #[must_use]
    pub fn measurement_replay_evidence(&self) -> &[CrucibleMeasurementReplayEvidence] {
        &self.measurement_replay_evidence
    }

    /// Returns the stores that yield every log segment the leaves reference.
    ///
    /// Publication stores each segment before any leaf that references it.
    #[must_use]
    pub const fn log_segments(&self) -> &AttemptLogSegmentSources {
        &self.log_segments
    }

    /// Rebinds the result to read its log and trace segments from
    /// `log_segments` only.
    ///
    /// The caller must already have copied every referenced attempt-log and
    /// resolved-effect trace segment there; later reads authenticate each
    /// segment against its reference.
    pub(crate) fn with_log_segments(mut self, log_segments: AttemptLogSegmentSources) -> Self {
        self.observation = self
            .observation
            .with_resolved_effect_trace_segments(log_segments.clone());
        if let Some(triage_replays) = self
            .finding
            .as_mut()
            .and_then(|finding| finding.triage_replays.as_mut())
        {
            triage_replays.segments = log_segments.clone();
        }
        self.log_segments = log_segments;
        self
    }

    /// Returns each attempt-log segment the finding's triage replay records
    /// name once, in record order.
    pub fn referenced_triage_segments(
        &self,
    ) -> Vec<crucible_campaign::FindingTriageReplayLogSegment> {
        self.finding
            .as_ref()
            .and_then(|finding| finding.triage_replays.as_ref())
            .map(|triage_replays| triage_replays.referenced_segments())
            .unwrap_or_default()
    }

    /// Returns each referenced log segment once, in leaf order.
    pub fn referenced_log_segments(&self) -> Vec<crate::AttemptLogSegmentRef> {
        referenced_segments(&self.measurement_replay_evidence)
    }

    /// Returns each retained finding replay record identity in table order.
    pub fn referenced_replay_records(&self) -> Vec<crucible_store::content_store::ContentId> {
        self.finding
            .as_ref()
            .map(|finding| finding.replay_records.ids.content_ids().collect())
            .unwrap_or_default()
    }

    /// Returns read handles to the stores that hold the retained replay records.
    ///
    /// A result without a finding retains no records and returns no stores.
    #[must_use]
    pub fn replay_record_sources(&self) -> ReplayRecordSources {
        self.finding
            .as_ref()
            .map(|finding| finding.replay_records.sources.clone())
            .unwrap_or_default()
    }

    /// Visits every retained finding replay record's canonical bytes in table order.
    ///
    /// Each record is read and authenticated before it is visited.
    pub(crate) fn try_for_each_replay_record<E>(
        &self,
        visit: impl FnMut(crucible_store::content_store::ContentId, &[u8]) -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<crate::ReplayRecordError>,
    {
        match &self.finding {
            Some(finding) => finding.replay_records.try_for_each_encoded(visit),
            None => Ok(()),
        }
    }

    /// Rebinds the result to read its replay records from `replay_records` only.
    ///
    /// The caller must already have copied every retained record there; later
    /// reads authenticate each record against its identity.
    pub(crate) fn with_replay_records(mut self, replay_records: ReplayRecordSources) -> Self {
        if let Some(finding) = &mut self.finding {
            finding.replay_records.sources = replay_records;
        }
        self
    }

    /// Returns each finding reproduction segment once, original first.
    ///
    /// The original and minimized schedules often share a prefix, and with it
    /// their leading segments, so a shared segment is listed once.
    pub fn referenced_reproduction_segments(&self) -> Vec<crucible_engine::segment_store::ContentId> {
        let Some(finding) = &self.finding else {
            return Vec::new();
        };
        let mut seen = BTreeSet::new();
        finding
            .original
            .payload_segments()
            .iter()
            .chain(finding.minimized.payload_segments())
            .map(|segment| segment.content())
            .filter(|segment| seen.insert(*segment))
            .collect()
    }

    /// Visits the bytes of each [`Self::referenced_reproduction_segments`]
    /// entry, in that order, encoding each from the finding's schedules.
    ///
    /// # Errors
    ///
    /// Returns the first error `visit` returns, or a codec error when a
    /// schedule cannot be segmented.
    pub(crate) fn try_for_each_reproduction_segment<E>(
        &self,
        mut visit: impl FnMut(crucible_engine::segment_store::ContentId, &[u8]) -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<PreparedSemanticResultCodecError>,
    {
        let Some(finding) = &self.finding else {
            return Ok(());
        };
        let mut seen = BTreeSet::new();
        for artifact in [&finding.original_artifact, &finding.minimized_artifact] {
            super::try_for_each_payload_segment(artifact.schedule(), |segment, bytes| {
                if !seen.insert(segment.content()) {
                    return Ok(());
                }
                visit(segment.content(), bytes).map_err(SegmentVisitError::Visit)
            })
            .map_err(|error| match error {
                SegmentVisitError::Visit(error) => error,
                SegmentVisitError::Payload(error) => {
                    E::from(PreparedSemanticResultCodecError::from(error))
                }
            })?;
        }
        Ok(())
    }

    /// Returns each resolved-effect trace segment the observation names, in
    /// trace order.
    pub fn referenced_trace_segments(&self) -> &[crucible_engine::segment_store::ContentId] {
        self.observation
            .observation()
            .resolved_effect_trace()
            .map_or(&[], |trace| trace.segments())
    }

    /// Checks the retained attempt trace against the authenticated scenario contract.
    ///
    /// The manifest must be canonical, within the authored fault resource
    /// limits, and list exactly the observation's segments; every segment is
    /// then read, authenticated, and decoded once, one at a time.
    ///
    /// # Errors
    ///
    /// Returns an error for a noncanonical manifest, a trace outside the
    /// authored fault resource limits, a segment list that differs from the
    /// observation's, or a segment that is absent, fails authentication, or
    /// holds an invalid work item.
    pub fn verify_resolved_effect_trace(
        &self,
        scenario: &ScenarioDefForm,
    ) -> Result<(), PreparedSemanticResultCodecError> {
        let (Some(reference), Some(manifest), Some(segments)) = (
            self.observation.observation().resolved_effect_trace(),
            self.observation.resolved_effect_trace_manifest(),
            self.observation.resolved_effect_trace_segments(),
        ) else {
            return Ok(());
        };

        let manifest = crucible_engine::model::ResolvedEffectTraceManifest::from_canonical_bytes(manifest)
            .map_err(|_| inconsistent("resolved-effect trace manifest"))?;
        manifest
            .admit(scenario.plan().fault_signals().resource_limits())
            .map_err(|_| inconsistent("resolved-effect trace contract"))?;
        if !manifest
            .segment_ids()
            .eq(reference.segments().iter().copied())
        {
            return Err(inconsistent("resolved-effect trace segment list"));
        }

        crucible_engine::model::ResolvedEffectTrace::referencing(manifest, segments.clone())
            .map_err(|_| inconsistent("resolved-effect trace segments"))?;
        Ok(())
    }

    /// Returns the complete terminal fingerprint set from completed terminal capture.
    #[must_use]
    pub fn terminal_fingerprints(&self) -> Option<&[FingerprintSample]> {
        self.terminal_fingerprints.as_deref()
    }

    /// Returns the prepared finding closure, when execution found one.
    #[must_use]
    pub const fn finding(&self) -> Option<&PreparedCrucibleFindingCandidate> {
        self.finding.as_ref()
    }

    pub(crate) fn production_replay_capture_inputs(
        &self,
    ) -> Result<
        Option<[crate::FindingReplayCaptureInput; 4]>,
        crate::FindingProductionReplayCaptureError,
    > {
        self.finding
            .as_ref()
            .map(PreparedCrucibleFindingCandidate::production_replay_capture_inputs)
            .transpose()
            .map(Option::flatten)
    }

    pub(crate) fn prepare_bound_production_replay_finding(
        &self,
        replay_captures: crucible_campaign::FindingReplayCaptureSet,
    ) -> Result<PreparedCrucibleFindingCandidate, PreparedSemanticResultCodecError> {
        let mut finding = self
            .finding
            .clone()
            .ok_or_else(|| inconsistent("finding production replay capture owner"))?;
        finding.bind_production_replay_captures(replay_captures)?;
        validate_pair(&self.observation, Some(&finding))?;
        Ok(finding)
    }

    pub(crate) fn commit_bound_production_replay_finding(
        &mut self,
        finding: PreparedCrucibleFindingCandidate,
    ) {
        self.finding = Some(finding);
    }

    /// Attaches one automatically prepared finding and its raw replay leaves.
    ///
    /// Existing observation measurement evidence is retained. Evidence reused
    /// by a finding replay is deduplicated by exact content identity before the
    /// complete observation/finding closure is revalidated.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedSemanticResultCodecError`] when this result already
    /// carries a finding, a replay leaf cannot be identified, or the combined
    /// evidence does not exactly cover the observation and finding records.
    pub(super) fn attach_finding(
        self,
        finding: PreparedCrucibleFindingCandidate,
        replay_evidence: Vec<CrucibleMeasurementReplayEvidence>,
        replay_segments: AttemptLogSegmentSources,
    ) -> Result<Self, PreparedSemanticResultCodecError> {
        if self.finding.is_some() {
            return Err(inconsistent("duplicate finding attachment"));
        }

        if self
            .measurement_replay_evidence
            .len()
            .checked_add(replay_evidence.len())
            .is_none_or(|records| records > MAX_PREPARED_RESULT_RECORDS)
        {
            return Err(PreparedSemanticResultCodecError::LimitExceeded);
        }

        let mut log_segments = self.log_segments;
        log_segments.extend(replay_segments);
        let mut evidence = BTreeMap::new();
        let mut evidence_bytes = 0_usize;
        for leaf in self
            .measurement_replay_evidence
            .into_iter()
            .chain(replay_evidence)
        {
            let id = leaf.id()?;
            match evidence.entry(id) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    evidence_bytes = evidence_bytes
                        .checked_add(leaf.canonical_bytes()?.len())
                        .and_then(|bytes| bytes.checked_add(size_of::<u32>()))
                        .ok_or(PreparedSemanticResultCodecError::LimitExceeded)?;
                    if evidence_bytes > MAX_PREPARED_SEMANTIC_RESULT_BYTES {
                        return Err(PreparedSemanticResultCodecError::LimitExceeded);
                    }
                    entry.insert(leaf);
                }
                std::collections::btree_map::Entry::Occupied(entry) if entry.get() == &leaf => {}
                std::collections::btree_map::Entry::Occupied(_) => {
                    return Err(inconsistent("conflicting measurement replay evidence"));
                }
            }
        }

        let terminal_fingerprints = self.terminal_fingerprints;
        let evidence = evidence.into_values().collect::<Vec<_>>();
        let result = Self::new(self.observation, evidence, log_segments, Some(finding))?;
        match terminal_fingerprints {
            Some(terminal_fingerprints) => result.with_terminal_fingerprints(terminal_fingerprints),
            None => Ok(result),
        }
    }

    /// Replays every retained measurement leaf against the authenticated scenario.
    ///
    /// Structural construction proves which measurement record owns each raw
    /// leaf. This operation additionally recomputes every derived evaluation
    /// from the scenario's exact definitions before any immutable publication.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedSemanticResultCodecError`] when the scenario differs
    /// from the prepared result or any raw replay disagrees with its retained
    /// measurement evaluation.
    pub fn verify_measurement_publications(
        &self,
        scenario: &ScenarioDefForm,
    ) -> Result<(), PreparedSemanticResultCodecError> {
        validate_measurement_evidence(
            &self.observation,
            &self.measurement_replay_evidence,
            &self.log_segments,
            self.finding.as_ref(),
        )?;

        let expected_scenario = super::campaign_scenario_id(scenario.id());
        if self.observation.child().scenario() != expected_scenario {
            return Err(inconsistent("authenticated measurement scenario"));
        }

        let evidence_by_id = self
            .measurement_replay_evidence
            .iter()
            .map(|leaf| leaf.id().map(|id| (id, leaf)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let observation_measurements = self.observation.measurements();
        verify_measurement_record(
            observation_measurements,
            self.observation.child().configuration(),
            expected_scenario,
            scenario,
            &evidence_by_id,
            &self.log_segments,
        )?;
        // Structural validation above visits every reference. Replay each
        // distinct retained evaluation/configuration pair once so repeated
        // minimization steps cannot multiply raw-leaf decoding work.
        let mut verified_pairs = BTreeSet::from([(
            observation_measurements.id()?,
            self.observation.child().configuration(),
        )]);

        let Some(finding) = &self.finding else {
            return Ok(());
        };
        let records = &finding.replay_records;
        let retained = RetainedMeasurementIds::new(records);
        let mut replay_count = 0usize;
        for replay in finding
            .minimization_replays
            .iter()
            .chain(&finding.verification_replays)
        {
            replay_count = replay_count
                .checked_add(1)
                .ok_or(PreparedSemanticResultCodecError::LimitExceeded)?;
            if replay_count > MAX_REPLAY_VALIDATION_REFERENCES {
                return Err(PreparedSemanticResultCodecError::LimitExceeded);
            }

            let Some((measurement_id, _, _, _, _)) = replay.observed_components() else {
                continue;
            };
            retained.measurement(measurement_id)?;
            retained.configuration(replay.configuration())?;
            let configuration = records.load::<ConfigurationArtifact>(replay.configuration())?;
            if verified_pairs.insert((measurement_id, configuration.configuration())) {
                let measurement = records.load::<MeasurementSet>(measurement_id)?;
                verify_measurement_record(
                    &measurement,
                    configuration.configuration(),
                    expected_scenario,
                    scenario,
                    &evidence_by_id,
                    &self.log_segments,
                )?;
            }
        }
        Ok(())
    }

    /// Verifies terminal samples against the authenticated scenario world.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedSemanticResultCodecError`] when the retained samples
    /// are not the exact canonical VM-node set of `scenario`.
    pub fn verify_terminal_fingerprints(
        &self,
        scenario: &ScenarioDefForm,
    ) -> Result<(), PreparedSemanticResultCodecError> {
        let Some(terminal_fingerprints) = &self.terminal_fingerprints else {
            return Ok(());
        };
        validate_terminal_fingerprints(terminal_fingerprints)?;

        let mut expected_nodes = scenario
            .world()
            .vm_nodes()
            .iter()
            .map(|node| node.id.clone())
            .collect::<Vec<_>>();
        expected_nodes.sort_by(|left, right| left.name.cmp(&right.name));
        let retained_nodes = terminal_fingerprints
            .iter()
            .map(|sample| sample.node.clone())
            .collect::<Vec<_>>();
        if retained_nodes != expected_nodes {
            return Err(inconsistent("terminal fingerprint world nodes"));
        }
        Ok(())
    }

    /// Returns strict, bounded journal payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedSemanticResultCodecError`] if validation or campaign
    /// identity derivation fails, or the complete payload exceeds its durable bound.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PreparedSemanticResultCodecError> {
        self.canonical_bytes_with_limit(MAX_PREPARED_SEMANTIC_RESULT_BYTES)
    }

    /// Returns strict journal bytes under a caller-selected operational limit.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedSemanticResultCodecError`] if validation fails or the
    /// payload exceeds the smaller of `maximum_bytes` and the format ceiling.
    pub fn canonical_bytes_with_limit(
        &self,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, PreparedSemanticResultCodecError> {
        validate_pair(&self.observation, self.finding.as_ref())?;
        if self
            .finding
            .as_ref()
            .is_some_and(|finding| finding.production_replays.is_some())
        {
            return Err(inconsistent("unbound finding production replay captures"));
        }
        if let Some(terminal_fingerprints) = &self.terminal_fingerprints {
            validate_terminal_fingerprints(terminal_fingerprints)?;
        }

        let mut encoder = Encoder::new(maximum_bytes.min(MAX_PREPARED_SEMANTIC_RESULT_BYTES));
        encoder.raw(PREPARED_RESULT_MAGIC_V10)?;
        encode_observation(&mut encoder, &self.observation)?;
        encode_measurement_evidence(&mut encoder, &self.measurement_replay_evidence)?;
        match &self.terminal_fingerprints {
            Some(terminal_fingerprints) => {
                encoder.byte(1)?;
                encode_terminal_fingerprints(&mut encoder, terminal_fingerprints)?;
            }
            None => encoder.byte(0)?,
        }
        match &self.finding {
            Some(finding) => {
                encoder.byte(1)?;
                encode_finding(&mut encoder, finding)?;
            }
            None => encoder.byte(0)?,
        }
        let bytes = encoder.finish()?;

        // Enforce the caller's operational byte ceiling before hashing raw
        // trace tables or reconstructing retained finding replay records.
        validate_log_segments(&self.measurement_replay_evidence, &self.log_segments)?;
        validate_measurement_evidence(
            &self.observation,
            &self.measurement_replay_evidence,
            &self.log_segments,
            self.finding.as_ref(),
        )?;
        if let Some(finding) = &self.finding {
            validate_finding(finding)?;
        }
        Ok(bytes)
    }

    /// Decodes and revalidates strict journal payload bytes.
    ///
    /// The payload names its log segments and finding replay records only by
    /// identity; `log_segments` and `replay_records` must yield every one of
    /// them.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedSemanticResultCodecError`] for truncated, trailing,
    /// oversized, noncanonical, or semantically inconsistent bytes, or when a
    /// referenced segment or replay record is absent or fails authentication.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        log_segments: impl Into<AttemptLogSegmentSources>,
        replay_records: impl Into<ReplayRecordSources>,
    ) -> Result<Self, PreparedSemanticResultCodecError> {
        Self::from_canonical_bytes_with_limit(
            bytes,
            MAX_PREPARED_SEMANTIC_RESULT_BYTES,
            log_segments,
            replay_records,
        )
    }

    /// Decodes strict journal bytes under a caller-selected operational limit.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedSemanticResultCodecError`] for invalid input, when
    /// its length exceeds the smaller of `maximum_bytes` and the format
    /// ceiling, or when a referenced segment or replay record is absent or
    /// fails authentication.
    pub fn from_canonical_bytes_with_limit(
        bytes: &[u8],
        maximum_bytes: usize,
        log_segments: impl Into<AttemptLogSegmentSources>,
        replay_records: impl Into<ReplayRecordSources>,
    ) -> Result<Self, PreparedSemanticResultCodecError> {
        let replay_records = replay_records.into();
        let log_segments = log_segments.into();
        let maximum_bytes = maximum_bytes.min(MAX_PREPARED_SEMANTIC_RESULT_BYTES);
        if bytes.len() > maximum_bytes {
            return Err(PreparedSemanticResultCodecError::LimitExceeded);
        }

        if !bytes.starts_with(PREPARED_RESULT_MAGIC_V10) {
            return Err(PreparedSemanticResultCodecError::Version);
        }
        let mut decoder = Decoder::new(bytes);
        decoder.magic(PREPARED_RESULT_MAGIC_V10)?;
        let observation = decode_observation(&mut decoder)?;
        let measurement_replay_evidence = decode_measurement_evidence(&mut decoder)?;
        let terminal_fingerprints = match decoder.byte()? {
            0 => None,
            1 => Some(decode_terminal_fingerprints(&mut decoder)?),
            _ => return Err(PreparedSemanticResultCodecError::InvalidTag),
        };
        let finding = match decoder.byte()? {
            0 => None,
            1 => Some(decode_finding(&mut decoder, replay_records, &log_segments)?),
            _ => return Err(PreparedSemanticResultCodecError::InvalidTag),
        };
        decoder.finish()?;

        // The payload names trace and reproduction segments only by identity,
        // like log segments; all are read from the caller's stores.
        let observation = observation.with_resolved_effect_trace_segments(log_segments.clone());
        let value = Self::new(
            observation,
            measurement_replay_evidence,
            log_segments,
            finding,
        )?;
        let value = match terminal_fingerprints {
            Some(terminal_fingerprints) => {
                value.with_terminal_fingerprints(terminal_fingerprints)?
            }
            None => value,
        };
        let canonical = value.canonical_bytes_with_limit(maximum_bytes)?;
        if canonical != bytes {
            return Err(PreparedSemanticResultCodecError::NonCanonical);
        }
        Ok(value)
    }

    /// Consumes the durable result into its exact publication records.
    #[must_use]
    pub fn into_parts(self) -> PreparedSemanticAttemptResultParts {
        PreparedSemanticAttemptResultParts {
            observation: self.observation,
            measurement_replay_evidence: self.measurement_replay_evidence,
            log_segments: self.log_segments,
            terminal_fingerprints: self.terminal_fingerprints,
            finding: self.finding,
        }
    }
}

/// The publication records of one consumed prepared result.
#[derive(Debug)]
pub struct PreparedSemanticAttemptResultParts {
    /// The complete canonical observation candidate.
    pub observation: ObservationCandidate,
    /// Raw measurement leaves in content-identity order.
    pub measurement_replay_evidence: Vec<CrucibleMeasurementReplayEvidence>,
    /// The stores that yield every log segment the leaves reference.
    pub log_segments: AttemptLogSegmentSources,
    /// The terminal fingerprint set, when terminal capture completed.
    pub terminal_fingerprints: Option<Vec<FingerprintSample>>,
    /// The prepared finding closure, when execution found one.
    pub finding: Option<PreparedCrucibleFindingCandidate>,
}

/// Failure to encode or authenticate a prepared semantic result.
#[derive(Debug, Error)]
pub enum PreparedSemanticResultCodecError {
    /// One nested campaign record was invalid.
    #[error(transparent)]
    Campaign(#[from] CampaignCodecError),
    /// Crucible replay or artifact validation rejected the closure.
    #[error(transparent)]
    Artifact(#[from] CrucibleArtifactError),
    /// Crucible rejected a raw measurement replay leaf.
    #[error(transparent)]
    Measurement(#[from] CrucibleMeasurementError),
    /// The payload ended before one declared value was complete.
    #[error("prepared semantic result is truncated")]
    Truncated,
    /// Bytes remained after the one expected result.
    #[error("prepared semantic result contains trailing bytes")]
    TrailingBytes,
    /// The payload declares a noncurrent format version.
    #[error("prepared semantic result uses an unsupported version")]
    Version,
    /// The payload contains an unsupported discriminant.
    #[error("prepared semantic result contains an invalid tag")]
    InvalidTag,
    /// The payload or one declared collection exceeds its bound.
    #[error("prepared semantic result exceeds its bounded journal limit")]
    LimitExceeded,
    /// Re-encoding produced different bytes.
    #[error("prepared semantic result is not canonically encoded")]
    NonCanonical,
    /// Nested records do not form one exact result closure.
    #[error("prepared semantic result has an inconsistent {component}")]
    Inconsistent {
        /// Stable component label.
        component: &'static str,
    },
    /// A retained finding replay record is absent or fails authentication.
    #[error(transparent)]
    ReplayRecord(#[from] crate::ReplayRecordError),
    /// A referenced attempt-log segment is absent or fails authentication.
    #[error("prepared semantic result log segment {segment} is unavailable: {source}")]
    LogSegment {
        /// Content identity of the referenced segment.
        segment: crucible_store::content_store::ContentId,
        /// Read or authentication failure.
        #[source]
        source: crate::AttemptEventLogError,
    },
}

fn validate_pair(
    observation: &ObservationCandidate,
    finding: Option<&PreparedCrucibleFindingCandidate>,
) -> Result<(), PreparedSemanticResultCodecError> {
    if observation.observation().resolved_effect_trace().is_some()
        != observation.resolved_effect_trace_manifest().is_some()
    {
        return Err(inconsistent("observation resolved-effect trace ownership"));
    }
    if let Some(manifest) = observation.resolved_effect_trace_manifest()
        && (manifest.len() > crucible_engine::model::MAX_RESOLVED_EFFECT_TRACE_MANIFEST_BYTES
            || observation
                .observation()
                .resolved_effect_trace()
                .map(crucible_campaign::ResolvedEffectTraceRef::manifest)
                != Some(crucible_store::content_store::ContentId::for_bytes(
                    crucible_store::content_store::ObjectKind::Trace,
                    crucible_engine::model::RESOLVED_EFFECT_TRACE_MANIFEST_SCHEMA,
                    manifest,
                )))
    {
        return Err(inconsistent("observation resolved-effect trace identity"));
    }
    let Some(finding) = finding else {
        return Ok(());
    };
    let observed = observation.observation();
    let signature = finding.bundle().signature();
    let child = observation.child().id()?;
    if finding.bundle().observation() != observed.id()? {
        return Err(inconsistent("finding observation"));
    }
    if finding.original_configuration().id()? != child
        || finding.original().configuration_artifact() != child
        || finding.original().scenario() != observation.child().scenario()
        || finding.original().finding_fingerprint() != signature.fingerprint()
    {
        return Err(inconsistent("finding observation reproduction basis"));
    }
    if signature.kind() == FindingKind::PropertyViolation {
        let property = signature
            .property()
            .ok_or_else(|| inconsistent("finding failed property"))?;
        if observation
            .properties()
            .properties()
            .get(property)
            .is_none_or(|evidence| evidence.verdict() != PropertyVerdict::Failed)
        {
            return Err(inconsistent("finding failed property"));
        }
    }
    match signature.target() {
        Some(FindingTarget::Configuration(target)) if target != child => {
            return Err(inconsistent("finding configuration target"));
        }
        Some(FindingTarget::ChoiceOpportunity(target)) if !observation.discovers(target) => {
            return Err(inconsistent("finding choice target"));
        }
        _ => {}
    }

    // The observation owns its fixed records directly and its choice records
    // through the paged sets whose bodies this candidate carries.
    let owned = BTreeSet::from([
        observed.attempt().content_id(),
        child.content_id(),
        observed.path().content_id(),
        observed.measurements().content_id(),
        observed.properties().content_id(),
        observed.coverage().content_id(),
    ]);
    for evidence in signature.causal_evidence() {
        if !owned.contains(evidence) && !observation.carries_choice_record(*evidence)? {
            return Err(inconsistent("finding causal evidence"));
        }
    }
    Ok(())
}

fn validate_measurement_evidence_order(
    evidence: &[CrucibleMeasurementReplayEvidence],
) -> Result<(), PreparedSemanticResultCodecError> {
    let mut previous = None;
    for leaf in evidence {
        let id = leaf.id()?;
        if previous == Some(id) {
            return Err(inconsistent("duplicate measurement replay evidence"));
        }
        if previous.is_some_and(|previous| previous > id) {
            return Err(inconsistent("measurement replay evidence order"));
        }
        previous = Some(id);
    }
    Ok(())
}

/// Returns each segment the leaves reference once, in first-reference order.
fn referenced_segments(
    evidence: &[CrucibleMeasurementReplayEvidence],
) -> Vec<crate::AttemptLogSegmentRef> {
    let mut seen = BTreeSet::new();
    evidence
        .iter()
        .flat_map(|leaf| leaf.segments().iter().copied())
        .filter(|segment| seen.insert(segment.id))
        .collect()
}

/// Requires `log_segments` to yield every referenced segment, authenticated.
///
/// Segments are read one at a time, so validation holds at most one segment
/// in memory regardless of the attempt log's length.
fn validate_log_segments(
    evidence: &[CrucibleMeasurementReplayEvidence],
    log_segments: &dyn AttemptLogSegmentSource,
) -> Result<(), PreparedSemanticResultCodecError> {
    for segment in referenced_segments(evidence) {
        let bytes = log_segments.segment(segment.id).map_err(|source| {
            PreparedSemanticResultCodecError::LogSegment {
                segment: segment.id,
                source: crate::AttemptEventLogError::Store { source },
            }
        })?;
        crate::decode_segment(&segment, &bytes).map_err(|source| {
            PreparedSemanticResultCodecError::LogSegment {
                segment: segment.id,
                source,
            }
        })?;
    }
    Ok(())
}

fn validate_terminal_fingerprints(
    terminal_fingerprints: &[FingerprintSample],
) -> Result<(), PreparedSemanticResultCodecError> {
    if terminal_fingerprints.len() > crate::MAX_QEMU_ATTEMPT_GENERATION_NODES {
        return Err(PreparedSemanticResultCodecError::LimitExceeded);
    }

    let mut previous = None;
    for sample in terminal_fingerprints {
        if sample.node.name.is_empty() {
            return Err(inconsistent("terminal fingerprint node name"));
        }
        if previous.is_some_and(|previous| previous >= sample.node.name.as_str()) {
            return Err(inconsistent("terminal fingerprint node order"));
        }
        previous = Some(sample.node.name.as_str());
    }
    Ok(())
}

/// Identities of the configuration and measurement records a finding retains.
///
/// A replay may name only retained records; a store holding other records
/// under those names does not make a reference valid.
struct RetainedMeasurementIds {
    configurations: BTreeSet<crucible_campaign::ConfigurationArtifactId>,
    measurements: BTreeSet<crucible_campaign::MeasurementSetId>,
}

impl RetainedMeasurementIds {
    fn new(records: &PreparedFindingReplayRecords) -> Self {
        Self {
            configurations: records.ids.configurations.iter().copied().collect(),
            measurements: records.ids.measurements.iter().copied().collect(),
        }
    }

    fn measurement(
        &self,
        id: crucible_campaign::MeasurementSetId,
    ) -> Result<(), PreparedSemanticResultCodecError> {
        if self.measurements.contains(&id) {
            Ok(())
        } else {
            Err(inconsistent("finding replay measurement record"))
        }
    }

    fn configuration(
        &self,
        id: crucible_campaign::ConfigurationArtifactId,
    ) -> Result<(), PreparedSemanticResultCodecError> {
        if self.configurations.contains(&id) {
            Ok(())
        } else {
            Err(inconsistent("finding replay measurement configuration"))
        }
    }
}

/// Returns whether any retained finding measurement needs raw replay evidence.
///
/// Records are read one at a time and the scan stops at the first match.
fn finding_measurement_requires_evidence(
    records: &PreparedFindingReplayRecords,
) -> Result<bool, PreparedSemanticResultCodecError> {
    for id in &records.ids.measurements {
        if measurement_requires_replay_evidence(&records.load::<MeasurementSet>(*id)?) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_measurement_evidence(
    observation: &ObservationCandidate,
    evidence: &[CrucibleMeasurementReplayEvidence],
    log_segments: &dyn AttemptLogSegmentSource,
    finding: Option<&PreparedCrucibleFindingCandidate>,
) -> Result<(), PreparedSemanticResultCodecError> {
    let observation_requires_evidence =
        measurement_requires_replay_evidence(observation.measurements());
    let finding_requires_evidence = match finding {
        Some(finding) => finding_measurement_requires_evidence(&finding.replay_records)?,
        None => false,
    };
    if evidence.is_empty() && !observation_requires_evidence && !finding_requires_evidence {
        return Ok(());
    }

    let evidence_by_id = evidence
        .iter()
        .map(|leaf| leaf.id().map(|id| (id, leaf)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    if evidence_by_id.len() != evidence.len() {
        return Err(inconsistent("duplicate measurement replay evidence"));
    }

    let mut owned = BTreeSet::new();
    validate_measurement_record(
        observation.measurements(),
        observation.child().scenario(),
        observation.child().configuration(),
        &evidence_by_id,
        &mut owned,
    )?;
    validate_observation_stop_evidence(observation, &evidence_by_id, log_segments)?;

    if let Some(finding) = finding {
        let retained = finding.bundle().exact_retention_evidence();
        match (
            observation.observation().stop(),
            retained.and_then(|value| value.assertion_boundary()),
        ) {
            (StopOutcome::AssertionFailure(property), Some(boundary)) => {
                let leaf = evidence_by_id
                    .get(&boundary.trace())
                    .ok_or_else(|| inconsistent("finding assertion trace"))?;
                if boundary.property() != property
                    || measurement_replay_leaf_id(
                        observation.measurements().evaluation().evidence(),
                    ) != Some(boundary.trace())
                    || leaf.scenario() != observation.child().scenario()
                    || leaf.configuration() != observation.child().configuration()
                    || !crate::crucible_measurement::verify_assertion_failure_boundary(
                        leaf,
                        log_segments,
                        boundary,
                    )
                {
                    return Err(inconsistent("finding assertion boundary"));
                }
            }
            (StopOutcome::AssertionFailure(_), None)
                if finding.bundle().exact_retention().disposition()
                    == crucible_campaign::FindingExactRetentionDisposition::Complete =>
            {
                return Err(inconsistent("finding assertion boundary is missing"));
            }
            (_, Some(_)) => return Err(inconsistent("finding assertion boundary stop")),
            _ => {}
        }
    }

    if let Some(finding) = finding {
        let referenced_measurements = finding
            .minimization_replays
            .iter()
            .chain(&finding.verification_replays)
            .filter_map(|replay| {
                replay
                    .observed_components()
                    .map(|(measurements, _, _, _, _)| measurements)
            })
            .collect::<BTreeSet<_>>();
        let records = &finding.replay_records;
        for id in &records.ids.measurements {
            let measurement = records.load::<MeasurementSet>(*id)?;
            if measurement_requires_replay_evidence(&measurement)
                && !referenced_measurements.contains(id)
            {
                return Err(inconsistent(
                    "unreferenced finding replay measurement record",
                ));
            }
        }

        // Each distinct measurement/configuration pair is validated once.
        let retained = RetainedMeasurementIds::new(records);
        let mut validated = BTreeSet::new();
        for replay in finding
            .minimization_replays
            .iter()
            .chain(&finding.verification_replays)
        {
            let Some((measurement_id, _, _, _, _)) = replay.observed_components() else {
                continue;
            };
            retained.measurement(measurement_id)?;
            if !validated.insert((measurement_id, replay.configuration())) {
                continue;
            }
            let measurement = records.load::<MeasurementSet>(measurement_id)?;
            if !measurement_requires_replay_evidence(&measurement) {
                continue;
            }
            retained.configuration(replay.configuration())?;
            let configuration = records.load::<ConfigurationArtifact>(replay.configuration())?;
            validate_measurement_record(
                &measurement,
                configuration.scenario(),
                configuration.configuration(),
                &evidence_by_id,
                &mut owned,
            )?;
        }
    }

    if owned.len() != evidence_by_id.len() {
        return Err(inconsistent("unowned measurement replay evidence"));
    }
    Ok(())
}

fn measurement_requires_replay_evidence(measurement: &MeasurementSet) -> bool {
    measurement.evaluation().payload_schema() == CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V3
}

fn validate_observation_stop_evidence(
    candidate: &ObservationCandidate,
    evidence_by_id: &BTreeMap<
        crucible_store::content_store::ContentId,
        &CrucibleMeasurementReplayEvidence,
    >,
    log_segments: &dyn AttemptLogSegmentSource,
) -> Result<(), PreparedSemanticResultCodecError> {
    let StopOutcome::ObservationReached(proof) = candidate.observation().stop() else {
        return Ok(());
    };
    let boundary = proof.boundary();
    if proof.child() != candidate.child().configuration()
        || boundary.start_completed_quanta().checked_add(1) != Some(boundary.completed_quanta())
    {
        return Err(inconsistent("observation stop boundary"));
    }

    let evaluation = candidate.measurements().evaluation();
    if evaluation.payload_schema() != CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V3 {
        return Err(inconsistent("observation stop measurement evidence"));
    }
    let evidence = measurement_replay_leaf_id(evaluation.evidence())
        .and_then(|id| evidence_by_id.get(&id).copied())
        .ok_or_else(|| inconsistent("observation stop measurement evidence"))?;

    // The leaf owns the exact boundary, prefix, and witness checks; the
    // result carries every segment the prefix spans.
    evidence
        .verify_observation_stop_proof(log_segments, proof)
        .map_err(|_| inconsistent("observation stop execution boundary"))
}

fn verify_measurement_record(
    measurement: &MeasurementSet,
    configuration: crucible_campaign::ConfigurationId,
    expected_scenario: crucible_campaign::ScenarioDefId,
    scenario: &ScenarioDefForm,
    evidence_by_id: &BTreeMap<
        crucible_store::content_store::ContentId,
        &CrucibleMeasurementReplayEvidence,
    >,
    log_segments: &dyn AttemptLogSegmentSource,
) -> Result<(), PreparedSemanticResultCodecError> {
    let evaluation = measurement.evaluation();
    if evaluation.payload_schema() != CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V3 {
        return Ok(());
    }
    let evidence_id = measurement_replay_leaf_id(evaluation.evidence())
        .ok_or_else(|| inconsistent("measurement replay evidence edge"))?;
    let evidence = evidence_by_id
        .get(&evidence_id)
        .copied()
        .ok_or_else(|| inconsistent("missing measurement replay evidence"))?;

    verify_crucible_measurement_publication(
        measurement,
        evidence,
        log_segments,
        expected_scenario,
        configuration,
        scenario.measurements(),
    )?;
    Ok(())
}

fn validate_measurement_record(
    measurement: &MeasurementSet,
    scenario: crucible_campaign::ScenarioDefId,
    configuration: crucible_campaign::ConfigurationId,
    evidence_by_id: &BTreeMap<
        crucible_store::content_store::ContentId,
        &CrucibleMeasurementReplayEvidence,
    >,
    owned: &mut BTreeSet<crucible_store::content_store::ContentId>,
) -> Result<(), PreparedSemanticResultCodecError> {
    let evaluation = measurement.evaluation();
    if evaluation.payload_schema() != CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V3 {
        return Ok(());
    }
    let evidence_id = measurement_replay_leaf_id(evaluation.evidence())
        .ok_or_else(|| inconsistent("measurement replay evidence edge"))?;
    let leaf = evidence_by_id
        .get(&evidence_id)
        .ok_or_else(|| inconsistent("missing measurement replay evidence"))?;
    if evaluation.evidence() != &leaf.evidence_ids()? {
        return Err(inconsistent("measurement replay evidence edge"));
    }
    if leaf.scenario() != scenario
        || leaf.configuration() != configuration
        || leaf.definitions() != evaluation.definitions()
    {
        return Err(inconsistent("measurement replay evidence binding"));
    }
    owned.insert(evidence_id);
    Ok(())
}

const fn inconsistent(component: &'static str) -> PreparedSemanticResultCodecError {
    PreparedSemanticResultCodecError::Inconsistent { component }
}

fn encode_observation(
    encoder: &mut Encoder,
    value: &ObservationCandidate,
) -> Result<(), PreparedSemanticResultCodecError> {
    encoder.record(&value.child().canonical_bytes())?;
    encoder.record(&value.measurements().canonical_bytes())?;
    encoder.record(&value.properties().canonical_bytes())?;
    encoder.record(&value.coverage().canonical_bytes())?;
    encoder.count(value.discovered_choices().len())?;
    for discovery in value.discovered_choices() {
        encoder.record(&discovery.declaration().canonical_bytes())?;
        encoder.record(&discovery.domain().canonical_bytes())?;
        encoder.record(&discovery.opportunity().canonical_bytes())?;
    }
    encoder.count(value.produced_selections().len())?;
    for selection in value.produced_selections() {
        encoder.record(&selection.canonical_bytes())?;
    }
    encoder.record(&value.observation().canonical_bytes())?;
    // Only the manifest is encoded; segments stay in the segment stores.
    match value.resolved_effect_trace_manifest() {
        Some(manifest) => {
            encoder.byte(1)?;
            encoder.record(manifest)?;
        }
        None => encoder.byte(0)?,
    }
    Ok(())
}

fn encode_measurement_evidence(
    encoder: &mut Encoder,
    evidence: &[CrucibleMeasurementReplayEvidence],
) -> Result<(), PreparedSemanticResultCodecError> {
    encoder.count(evidence.len())?;
    for leaf in evidence {
        encoder.record(&leaf.canonical_bytes()?)?;
    }
    Ok(())
}

fn decode_measurement_evidence(
    decoder: &mut Decoder<'_>,
) -> Result<Vec<CrucibleMeasurementReplayEvidence>, PreparedSemanticResultCodecError> {
    let count = decoder.count()?;
    decoder.preflight_collection(count, size_of::<u32>())?;
    let mut evidence = Vec::with_capacity(count);
    for _ in 0..count {
        evidence.push(CrucibleMeasurementReplayEvidence::from_canonical_bytes(
            decoder.record()?,
        )?);
    }
    Ok(evidence)
}

fn encode_terminal_fingerprints(
    encoder: &mut Encoder,
    terminal_fingerprints: &[FingerprintSample],
) -> Result<(), PreparedSemanticResultCodecError> {
    validate_terminal_fingerprints(terminal_fingerprints)?;
    encoder.count(terminal_fingerprints.len())?;
    for sample in terminal_fingerprints {
        encoder.record(sample.node.name.as_bytes())?;
        encoder.raw(&sample.at.ticks.to_be_bytes())?;
        encoder.raw(&sample.fingerprint.hash.bytes)?;
    }
    Ok(())
}

fn decode_terminal_fingerprints(
    decoder: &mut Decoder<'_>,
) -> Result<Vec<FingerprintSample>, PreparedSemanticResultCodecError> {
    let count = decoder.count_bounded(crate::MAX_QEMU_ATTEMPT_GENERATION_NODES)?;
    decoder.preflight_collection(count, size_of::<u32>() + size_of::<u64>() + 32)?;

    let mut terminal_fingerprints = Vec::with_capacity(count);
    for _ in 0..count {
        let node = std::str::from_utf8(decoder.record()?)
            .map_err(|_| inconsistent("terminal fingerprint node name"))?
            .to_owned();
        let ticks = u64::from_be_bytes(
            decoder
                .take(size_of::<u64>())?
                .try_into()
                .map_err(|_| PreparedSemanticResultCodecError::Truncated)?,
        );
        let hash = decoder
            .take(32)?
            .try_into()
            .map_err(|_| PreparedSemanticResultCodecError::Truncated)?;
        terminal_fingerprints.push(FingerprintSample {
            node: NodeId { name: node },
            at: VirtualTime { ticks },
            fingerprint: ExecutionFingerprint {
                hash: ContentHash { bytes: hash },
            },
        });
    }
    validate_terminal_fingerprints(&terminal_fingerprints)?;
    Ok(terminal_fingerprints)
}

fn decode_observation(
    decoder: &mut Decoder<'_>,
) -> Result<ObservationCandidate, PreparedSemanticResultCodecError> {
    let child = decoder.decode_record(ConfigurationArtifact::from_canonical_bytes)?;
    let measurements = decoder.decode_record(MeasurementSet::from_canonical_bytes)?;
    let properties = decoder.decode_record(PropertyVerdictSet::from_canonical_bytes)?;
    let coverage = decoder.decode_record(CoverageProjection::from_canonical_bytes)?;
    let discovery_count = decoder.count()?;
    decoder.preflight_collection(discovery_count, 3 * size_of::<u32>())?;
    let mut discoveries = Vec::with_capacity(discovery_count);
    for _ in 0..discovery_count {
        discoveries.push(ChoiceDiscovery::new(
            decoder.decode_record(SelectableDeclaration::from_canonical_bytes)?,
            decoder.decode_record(ChoiceDomain::from_canonical_bytes)?,
            decoder.decode_record(ChoiceOpportunity::from_canonical_bytes)?,
        )?);
    }
    let selection_count = decoder.count()?;
    decoder.preflight_collection(selection_count, size_of::<u32>())?;
    let mut selections = Vec::with_capacity(selection_count);
    for _ in 0..selection_count {
        selections.push(decoder.decode_record(Selection::from_canonical_bytes)?);
    }
    let observation = decoder.decode_record(Observation::from_canonical_bytes)?;

    let candidate = ObservationCandidate::from_recorded_parts(
        child,
        measurements,
        properties,
        coverage,
        discoveries,
        selections,
        observation,
    )?;
    match decoder.byte()? {
        0 => Ok(candidate),
        // The caller rebinds the segments to its stores after decoding.
        1 => candidate
            .with_resolved_effect_trace(
                decoder.record()?.to_vec(),
                crucible_engine::segment_store::SegmentSources::default(),
            )
            .map_err(Into::into),
        _ => Err(PreparedSemanticResultCodecError::InvalidTag),
    }
}

fn encode_finding(
    encoder: &mut Encoder,
    value: &PreparedCrucibleFindingCandidate,
) -> Result<(), PreparedSemanticResultCodecError> {
    encoder.byte(discovery_path_tag(value.discovery_path))?;
    encoder.raw(&value.minimization_seed.bytes())?;
    encoder.record(&value.scenario.canonical_bytes())?;
    encoder.record(&value.original_configuration.canonical_bytes())?;
    encoder.record(&value.original.canonical_bytes())?;
    encoder.record(&value.minimized_configuration.canonical_bytes())?;
    encoder.record(&value.minimized.canonical_bytes())?;
    encode_record_ids(encoder, &value.replay_records.ids)?;
    encode_replays(encoder, value)?;
    let Some(triage_replays) = &value.triage_replays else {
        return Err(inconsistent("finding triage replay evidence"));
    };
    for replay in triage_replays.records() {
        encoder.record(&replay.canonical_bytes())?;
    }
    encoder.record(&value.bundle.canonical_bytes())?;
    Ok(())
}

/// A caller's visit error, or a schedule that could not be segmented.
enum SegmentVisitError<E> {
    Visit(E),
    Payload(CrucibleArtifactError),
}

impl<E> From<CrucibleArtifactError> for SegmentVisitError<E> {
    fn from(error: CrucibleArtifactError) -> Self {
        Self::Payload(error)
    }
}

fn decode_finding(
    decoder: &mut Decoder<'_>,
    replay_record_sources: ReplayRecordSources,
    segments: &AttemptLogSegmentSources,
) -> Result<PreparedCrucibleFindingCandidate, PreparedSemanticResultCodecError> {
    let discovery_path = discovery_path_from_tag(decoder.byte()?)?;
    let minimization_seed = crucible_engine::Seed::from_bytes(
        decoder
            .take(32)?
            .try_into()
            .map_err(|_| PreparedSemanticResultCodecError::Truncated)?,
    );
    let scenario = decoder.decode_record(ScenarioArtifact::from_canonical_bytes)?;
    let original_configuration =
        decoder.decode_record(ConfigurationArtifact::from_canonical_bytes)?;
    let original = decoder.decode_record(ReproductionArtifact::from_canonical_bytes)?;
    let original_artifact = super::decode_crucible_reproduction(
        &original,
        segments,
        "journal original finding reproduction",
    )?;
    let minimized_configuration =
        decoder.decode_record(ConfigurationArtifact::from_canonical_bytes)?;
    let minimized = decoder.decode_record(ReproductionArtifact::from_canonical_bytes)?;
    let minimized_artifact = super::decode_crucible_reproduction(
        &minimized,
        segments,
        "journal minimized finding reproduction",
    )?;
    let (replay_record_ids, record_count, record_bytes) =
        decode_record_ids(decoder, &replay_record_sources)?;
    let mut replay_validation_references = 0usize;
    let minimization_indexes = decode_replay_indexes(decoder, &mut replay_validation_references)?;
    let verification_indexes = decode_replay_indexes(decoder, &mut replay_validation_references)?;
    let triage_replays = Some(PreparedFindingTriageReplayRecords {
        minimization_original: decoder
            .decode_record(FindingTriageReplayEvidence::from_canonical_bytes)?,
        minimization_selected: decoder
            .decode_record(FindingTriageReplayEvidence::from_canonical_bytes)?,
        verification_original: decoder
            .decode_record(FindingTriageReplayEvidence::from_canonical_bytes)?,
        verification_selected: decoder
            .decode_record(FindingTriageReplayEvidence::from_canonical_bytes)?,
        segments: segments.clone(),
    });
    let bundle = decoder.decode_record(FindingCandidateBundle::from_canonical_bytes)?;

    // Identity tables were typed by authenticating each record once, so
    // compact replay indexes resolve without rehashing any record.
    let ids = &replay_record_ids;
    let minimization_replays = materialize_replays(
        &minimization_indexes,
        ReplayMaterialTables {
            signatures: bundle.signature_minimization().minimization_pass(),
            configurations: &ids.configurations,
            measurements: &ids.measurements,
            properties: &ids.properties,
            coverage: &ids.coverage,
            opportunities: &ids.opportunities,
            selections: &ids.selections,
        },
    )?;
    let verification_replays = materialize_replays(
        &verification_indexes,
        ReplayMaterialTables {
            signatures: bundle.signature_minimization().verification_pass(),
            configurations: &ids.configurations,
            measurements: &ids.measurements,
            properties: &ids.properties,
            coverage: &ids.coverage,
            opportunities: &ids.opportunities,
            selections: &ids.selections,
        },
    )?;

    let signature_bytes = bundle
        .signature_minimization()
        .minimization_pass()
        .iter()
        .chain(bundle.signature_minimization().verification_pass().iter())
        .flatten()
        .fold(0_u64, |total, signature| {
            total.saturating_add(signature.canonical_bytes().len() as u64)
        });
    let canonical_bytes = record_bytes.saturating_add(signature_bytes);
    if canonical_bytes > MAX_CRUCIBLE_FINDING_REPLAY_BYTES {
        return Err(PreparedSemanticResultCodecError::LimitExceeded);
    }
    let replay_records = PreparedFindingReplayRecords {
        ids: replay_record_ids,
        sources: replay_record_sources,
        record_count,
        canonical_bytes,
    };
    let value = PreparedCrucibleFindingCandidate {
        discovery_path,
        minimization_seed,
        scenario,
        original_configuration,
        original,
        original_artifact,
        minimized_configuration,
        minimized,
        minimized_artifact,
        replay_records,
        minimization_replays,
        verification_replays,
        triage_replays,
        production_replays: None,
        bundle,
    };
    validate_finding(&value)?;
    Ok(value)
}

fn validate_finding(
    value: &PreparedCrucibleFindingCandidate,
) -> Result<(), PreparedSemanticResultCodecError> {
    let scenario = value.scenario.scenario();
    let original_configuration = value.original_configuration.id()?;
    let minimized_configuration = value.minimized_configuration.id()?;
    let original = value.original.id()?;
    let minimized = value.minimized.id()?;
    if value.original_configuration.scenario() != scenario
        || value.minimized_configuration.scenario() != scenario
        || value.original.configuration_artifact() != original_configuration
        || value.minimized.configuration_artifact() != minimized_configuration
        || value.bundle.reproduction() != original
        || value.bundle.minimized() != minimized
    {
        return Err(PreparedSemanticResultCodecError::Inconsistent {
            component: "finding reproduction closure",
        });
    }

    validate_recorded_replays(value)?;
    let original_finding = decode_journal_finding_reproduction(
        &value.original,
        &value.original_artifact,
        value.discovery_path,
        "journal original finding reproduction",
    )?;
    let (expected_scenario, expected_configuration, expected_original) =
        prepare_original_reproduction(&original_finding)?;
    if expected_scenario != value.scenario
        || expected_configuration != value.original_configuration
        || expected_original != value.original
    {
        return Err(PreparedSemanticResultCodecError::Inconsistent {
            component: "original finding reconstruction",
        });
    }

    let signature = value.bundle.signature();
    let minimization = replay_recorded_signature_pass(
        &original_finding,
        signature,
        value.minimization_seed,
        &value.minimization_replays,
    )?;
    let verification = replay_recorded_signature_pass(
        &original_finding,
        signature,
        value.minimization_seed,
        &value.verification_replays,
    )?;
    if minimization != verification {
        return Err(PreparedSemanticResultCodecError::Inconsistent {
            component: "finding replay passes",
        });
    }
    super::validate_replay_incompatibility_passes(
        &value.minimization_replays,
        &value.verification_replays,
    )?;
    let (expected_minimized_configuration, expected_minimized) =
        prepare_minimized_reproduction(original, &minimization)?;
    if expected_minimized_configuration != value.minimized_configuration
        || expected_minimized != value.minimized
    {
        return Err(PreparedSemanticResultCodecError::Inconsistent {
            component: "minimized finding reconstruction",
        });
    }
    let minimized_finding = decode_journal_finding_reproduction(
        &value.minimized,
        &value.minimized_artifact,
        value.discovery_path,
        "journal minimized finding reproduction",
    )?;
    validate_finding_triage_replays(value, &original_finding, &minimized_finding)?;
    Ok(())
}

/// Replays a journal reproduction's Crucible artifact into a finding.
///
/// The artifact's correspondence to `reproduction` is checked by the caller,
/// which re-derives the record from the returned finding.
fn decode_journal_finding_reproduction(
    reproduction: &ReproductionArtifact,
    artifact: &crucible_engine::ReproductionArtifact,
    discovery_path: crucible_engine::FindingDiscoveryPath,
    artifact_name: &'static str,
) -> Result<FindingReproductionArtifact, PreparedSemanticResultCodecError> {
    let artifact = artifact.clone();
    let replay = artifact
        .replay()
        .map_err(|source| CrucibleArtifactError::InvalidPayload {
            artifact: artifact_name,
            source: Box::new(source),
        })?;
    let configuration = crucible_engine::Configuration {
        def: artifact.scenario_def(),
        schedule: artifact.schedule().clone(),
    }
    .id();

    Ok(FindingReproductionArtifact {
        discovery_path,
        finding_fingerprint: ContentHash {
            bytes: reproduction.finding_fingerprint().as_bytes(),
        },
        configuration,
        artifact,
        replay,
    })
}

impl PreparedCrucibleFindingCandidate {
    pub(crate) fn production_replay_capture_limits(
        &self,
    ) -> Result<crate::FindingProductionReplayCaptureLimits, PreparedSemanticResultCodecError> {
        let finding = decode_journal_finding_reproduction(
            &self.original,
            &self.original_artifact,
            self.discovery_path,
            "journal production replay capture basis",
        )?;
        Ok(crate::FindingProductionReplayCaptureLimits::for_finding(
            &finding,
        ))
    }
}

fn validate_finding_triage_replays(
    value: &PreparedCrucibleFindingCandidate,
    original_finding: &FindingReproductionArtifact,
    minimized_finding: &FindingReproductionArtifact,
) -> Result<(), PreparedSemanticResultCodecError> {
    let Some(triage_replays) = &value.triage_replays else {
        if value.bundle.triage_evidence().is_some() {
            return Err(inconsistent("finding triage replay evidence"));
        }
        return Ok(());
    };
    let retained_ids = triage_replays.evidence_set()?;
    if value.bundle.triage_evidence() != Some(retained_ids) {
        return Err(inconsistent("finding triage replay evidence identities"));
    }

    let minimization = value
        .minimized
        .minimization()
        .ok_or_else(|| inconsistent("finding triage minimization"))?;
    let selected_index = minimization
        .attempts()
        .iter()
        .position(|attempt| attempt.accepted())
        .map_or(0, |index| index + 1);
    let signatures = value.bundle.signature_minimization();
    let minimization_original = signatures
        .minimization_pass()
        .first()
        .and_then(Option::as_ref)
        .ok_or_else(|| inconsistent("finding triage minimization original signature"))?;
    let minimization_selected = signatures
        .minimization_pass()
        .get(selected_index)
        .and_then(Option::as_ref)
        .ok_or_else(|| inconsistent("finding triage minimization selected signature"))?;
    let verification_original = signatures
        .verification_pass()
        .first()
        .and_then(Option::as_ref)
        .ok_or_else(|| inconsistent("finding triage verification original signature"))?;
    let verification_selected = signatures
        .verification_pass()
        .get(selected_index)
        .and_then(Option::as_ref)
        .ok_or_else(|| inconsistent("finding triage verification selected signature"))?;

    for (record, reproduction, signature, finding) in [
        (
            &triage_replays.minimization_original,
            value.bundle.reproduction(),
            minimization_original,
            original_finding,
        ),
        (
            &triage_replays.minimization_selected,
            value.bundle.minimized(),
            minimization_selected,
            minimized_finding,
        ),
        (
            &triage_replays.verification_original,
            value.bundle.reproduction(),
            verification_original,
            original_finding,
        ),
        (
            &triage_replays.verification_selected,
            value.bundle.minimized(),
            verification_selected,
            minimized_finding,
        ),
    ] {
        if record.reproduction() != reproduction
            || record.observed_signature() != signature
            || !FailureTriageReplayEvidence::supports_schema(record.payload_schema())
        {
            return Err(inconsistent("finding triage replay evidence basis"));
        }
        let native_replay = FailureTriageReplayEvidence::from_compact_binary(
            finding.clone(),
            record.payload(),
            std::sync::Arc::new(triage_replays.segments.clone()),
        )
        .map_err(|source| CrucibleArtifactError::InvalidPayload {
            artifact: "journal finding triage replay evidence",
            source: Box::new(source),
        })?;
        if record.payload_schema() != native_replay.schema_version() {
            return Err(inconsistent(
                "finding triage replay declared payload schema",
            ));
        }
        // The record must name exactly the segments its payload references,
        // or retention would diverge from what verification reads.
        let referenced = native_replay.referenced_segments();
        if record.log_segments().len() != referenced.len()
            || record
                .log_segments()
                .iter()
                .zip(&referenced)
                .any(|(named, segment)| {
                    named.content() != segment.id || named.bytes() != segment.encoded_bytes
                })
        {
            return Err(inconsistent("finding triage replay log segments"));
        }
        let native_signature = native_replay.signature();
        let native_kind = match native_signature.failure_kind {
            FailureKind::PropertyViolation => FindingKind::PropertyViolation,
            FailureKind::Divergence => FindingKind::Divergence,
            FailureKind::Timeout => FindingKind::Timeout,
        };
        let native_property = native_signature
            .property
            .as_ref()
            .map(|property| property.id.name.as_str());

        if native_kind != signature.kind() || native_property != signature.property() {
            return Err(inconsistent(
                "finding triage replay native signature policy key",
            ));
        }
        validate_native_divergence_fingerprint(signature, finding, native_replay.failure())?;
    }
    Ok(())
}

fn validate_native_divergence_fingerprint(
    signature: &FindingSignature,
    finding: &FindingReproductionArtifact,
    failure: &FailureClusterReportFailure,
) -> Result<(), PreparedSemanticResultCodecError> {
    let FailureClusterReportFailure::Divergence(divergence) = failure else {
        return Ok(());
    };
    let scenario = super::campaign_scenario_id(finding.artifact.scenario_form().id());
    let fingerprint =
        crate::automatic_finding_runner::divergence_fingerprint_for_scenario(scenario, divergence);
    if fingerprint != signature.fingerprint() {
        return Err(inconsistent(
            "finding triage replay native divergence fingerprint",
        ));
    }
    Ok(())
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- the integrity fixture uses panic shortcuts for exact failure localization.
#[allow(clippy::expect_used)]
mod triage_replay_tests {
    use super::*;

    fn divergence(node: &str) -> crucible_engine::FailureClusterReportDivergence {
        let node = NodeId {
            name: node.to_owned(),
        };
        crucible_engine::FailureClusterReportDivergence {
            raw_index: 0,
            node: Some(node.clone()),
            icount_node: Some(node),
            tick: crucible_engine::SimInstant { ticks: 1 },
            icount: Some(crucible_engine::Icount { retired: 1 }),
            source: crucible_engine::EventSource::Engine,
            kind: String::from("fork"),
            expected_state_summary: String::from("expected"),
            reproduced_state_summary: String::from("reproduced"),
        }
    }

    #[test]
    fn native_divergence_payload_swap_must_match_recorded_fingerprint() {
        let scenario = crucible_engine::happy_path_scenario()
            .expect("happy-path scenario")
            .scenario;
        let configuration = crucible_engine::Configuration::genesis(scenario.scenario_def());
        let expected_divergence = divergence("node-a");
        let scenario_id = super::super::campaign_scenario_id(scenario.id());
        let fingerprint = crate::automatic_finding_runner::divergence_fingerprint_for_scenario(
            scenario_id,
            &expected_divergence,
        );
        let observed = FindingSignature::new(
            FindingKind::Divergence,
            fingerprint,
            None,
            String::from("qemu.causal-log-divergence"),
            None,
            BTreeSet::new(),
        )
        .expect("observed divergence signature");
        let finding = FindingReproductionArtifact::capture(
            crucible_engine::FindingDiscoveryPath::StateSpaceSearch,
            ContentHash {
                bytes: fingerprint.as_bytes(),
            },
            &scenario,
            &configuration,
        )
        .expect("finding reproduction");
        let expected = FailureClusterReportFailure::divergence(expected_divergence);
        let swapped = FailureClusterReportFailure::divergence(divergence("node-b"));

        validate_native_divergence_fingerprint(&observed, &finding, &expected)
            .expect("production-derived divergence fingerprint");
        assert!(matches!(
            validate_native_divergence_fingerprint(&observed, &finding, &swapped),
            Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "finding triage replay native divergence fingerprint"
            })
        ));
    }
}
