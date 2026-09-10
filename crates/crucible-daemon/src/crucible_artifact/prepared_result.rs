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
//! v5-magic
//! observation, raw measurements, optional terminal fingerprints, and replay indexes as v4
//! four role-specific finding-triage replay records before the finding bundle
//! ```
//!
//! ```text
//! v4-magic
//! observation and raw measurement records as v3
//! optional terminal-fingerprint records
//! finding closure with tagged observed or deterministically-incompatible replay indexes
//! ```
//!
//! ```text
//! v3-magic
//! observation-child, measurements, properties, coverage
//! discovered-choice-count, discovered-choice records
//! produced-selection-count, selection records, observation
//! measurement-replay-evidence-count, measurement-replay-evidence records
//! terminal-fingerprint-count, terminal-fingerprint records
//! finding-present
//! [discovery-path, minimization-seed, scenario, original configuration,
//!  original reproduction, minimized configuration, minimized reproduction,
//!  deduplicated replay record tables, two replay-index passes, finding bundle]
//! ```
//!
//! ```text
//! v2-magic
//! observation-child, measurements, properties, coverage
//! discovered-choice-count, discovered-choice records
//! produced-selection-count, selection records, observation
//! measurement-replay-evidence-count, measurement-replay-evidence records
//! finding-present
//! [discovery-path, minimization-seed, scenario, original configuration,
//!  original reproduction, minimized configuration, minimized reproduction,
//!  deduplicated replay record tables, two replay-index passes, finding bundle]
//! ```
//!
//! Every record is a u32-length-prefixed canonical body. Counts and indexes are
//! u32 values. Decoding caps the complete payload at 1 GiB, each record at 64
//! MiB, and replay reconstruction by both record and referenced-byte budgets.
//!
//! Raw-leaf validation here proves structural ownership: exact trace identity,
//! singleton measurement edge, and scenario, configuration, and definition
//! bindings. It also authenticates an observation-stop proof against the owned
//! raw event prefix and terminal evidence. This codec does not possess
//! authenticated scenario measurement definitions and therefore does not
//! replay the leaf or compare the retained evaluation payload. Production
//! preparation and recovery must call
//! [`crate::verify_crucible_measurement_publication`] for the observation and
//! every finding replay before any child-first publication.

use std::collections::{BTreeMap, BTreeSet};

use crucible::{
    AssertionPhase, ContentHash, ExecutionFingerprint, FailureKind, FailureTriageReplayEvidence,
    FindingReproductionArtifact, FingerprintSample, NodeId, ObservableEventPayload,
    ScenarioDefForm, SchedulerEventLogEntry, SchedulerEventLogPayload, VirtualTime,
};
use crucible_campaign::{
    CampaignCodecError, CampaignHash, ChoiceDiscovery, ChoiceDomain, ChoiceOpportunity,
    ConfigurationArtifact, CoverageProjection, FindingCandidateBundle, FindingKind, FindingTarget,
    FindingTriageReplayEvidence, MeasurementSet, Observation, ObservationCandidate,
    ObservationCondition, ObservationStopSatisfaction, PropertyVerdict, PropertyVerdictSet,
    ReproductionArtifact, ScenarioArtifact, SelectableDeclaration, Selection, StopOutcome,
};
use thiserror::Error;

use super::finding_replay::PreparedFindingReplayRecords;
use super::{
    CrucibleArtifactError, FindingReplayIncompatibility, MAX_CRUCIBLE_FINDING_REPLAY_BYTES,
    MAX_CRUCIBLE_FINDING_REPLAY_RECORDS, PreparedCrucibleFindingCandidate,
    PreparedFindingTriageReplayRecords, RecordedFindingReplay, prepare_minimized_reproduction,
    prepare_original_reproduction, replay_recorded_signature_pass,
};
use crate::{
    CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V2, CrucibleMeasurementError,
    CrucibleMeasurementReplayEvidence, verify_crucible_measurement_publication,
};

const PREPARED_RESULT_MAGIC_V1: &[u8] = b"crucible.executor.prepared-semantic-attempt-result.v1\0";
const PREPARED_RESULT_MAGIC_V2: &[u8] = b"crucible.executor.prepared-semantic-attempt-result.v2\0";
const PREPARED_RESULT_MAGIC_V3: &[u8] = b"crucible.executor.prepared-semantic-attempt-result.v3\0";
const PREPARED_RESULT_MAGIC_V4: &[u8] = b"crucible.executor.prepared-semantic-attempt-result.v4\0";
const PREPARED_RESULT_MAGIC_V5: &[u8] = b"crucible.executor.prepared-semantic-attempt-result.v5\0";
pub(super) const MAX_PREPARED_RESULT_RECORDS: usize = 200_000;
const MAX_RECORD_BYTES: usize = 64 * 1024 * 1024;
const MAX_REPLAY_VALIDATION_REFERENCES: usize = 4 * 1024 * 1024;

/// Maximum encoded bytes retained by one prepared semantic result journal.
pub const MAX_PREPARED_SEMANTIC_RESULT_BYTES: usize = 1024 * 1024 * 1024;

/// Complete immutable semantic result retained across publication retries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedSemanticAttemptResult {
    observation: ObservationCandidate,
    measurement_replay_evidence: Vec<CrucibleMeasurementReplayEvidence>,
    terminal_fingerprints: Option<Vec<FingerprintSample>>,
    finding: Option<PreparedCrucibleFindingCandidate>,
}

impl PreparedSemanticAttemptResult {
    /// Binds one observation to its optional prepared finding closure.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedSemanticResultCodecError`] when the finding does not
    /// belong to the observation or its scenario, configuration, failed property,
    /// target, or causal evidence.
    pub fn new(
        observation: ObservationCandidate,
        finding: Option<PreparedCrucibleFindingCandidate>,
    ) -> Result<Self, PreparedSemanticResultCodecError> {
        Self::new_with_measurement_replay_evidence(observation, Vec::new(), finding)
    }

    /// Binds an observation and finding to all required raw measurement leaves.
    ///
    /// The leaves are retained in content-identity order, and duplicates are
    /// rejected. The supplied set must exactly cover every Crucible measurement
    /// payload v2 referenced by the observation and both finding replay passes.
    /// This authenticates closure ownership and any observation-stop proof;
    /// callers must separately run [`crate::verify_crucible_measurement_publication`]
    /// with the authenticated scenario definitions before publication.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedSemanticResultCodecError`] when a leaf is duplicated,
    /// unowned, absent, or bound to a different scenario, configuration, or
    /// measurement definition, or when the finding does not belong to the
    /// observation.
    pub fn new_with_measurement_replay_evidence(
        observation: ObservationCandidate,
        measurement_replay_evidence: Vec<CrucibleMeasurementReplayEvidence>,
        finding: Option<PreparedCrucibleFindingCandidate>,
    ) -> Result<Self, PreparedSemanticResultCodecError> {
        validate_measurement_evidence_order(&measurement_replay_evidence)?;
        validate_pair(&observation, finding.as_ref())?;
        validate_measurement_evidence(
            &observation,
            &measurement_replay_evidence,
            finding.as_ref(),
        )?;
        Ok(Self {
            observation,
            measurement_replay_evidence,
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
    pub fn attach_finding(
        self,
        finding: PreparedCrucibleFindingCandidate,
        replay_evidence: Vec<CrucibleMeasurementReplayEvidence>,
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

        let mut evidence = BTreeMap::new();
        let mut evidence_bytes = 0usize;
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
        let result = Self::new_with_measurement_replay_evidence(
            self.observation,
            evidence.into_values().collect(),
            Some(finding),
        )?;
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
        )?;
        // Structural validation above visits every reference. Replay each
        // distinct retained evaluation/configuration pair once so repeated
        // minimization steps cannot multiply raw-leaf decoding work.
        let mut verified_pairs = BTreeSet::from([(
            observation_measurements.id()?,
            self.observation.child().configuration(),
        )]);

        let finding_records = self
            .finding
            .as_ref()
            .map(|finding| {
                let configurations = finding
                    .replay_records
                    .configurations
                    .iter()
                    .map(|record| record.id().map(|id| (id, record.configuration())))
                    .collect::<Result<BTreeMap<_, _>, _>>()?;
                let measurements = finding
                    .replay_records
                    .measurements
                    .iter()
                    .map(|record| record.id().map(|id| (id, record)))
                    .collect::<Result<BTreeMap<_, _>, _>>()?;
                Ok::<_, PreparedSemanticResultCodecError>((finding, configurations, measurements))
            })
            .transpose()?;

        if let Some((finding, configurations, measurements)) = &finding_records {
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

                let measurement = measurements
                    .get(&measurement_id)
                    .ok_or_else(|| inconsistent("finding replay measurement record"))?;
                let configuration = configurations
                    .get(&replay.configuration())
                    .copied()
                    .ok_or_else(|| inconsistent("finding replay measurement configuration"))?;
                if verified_pairs.insert((measurement_id, configuration)) {
                    verify_measurement_record(
                        measurement,
                        configuration,
                        expected_scenario,
                        scenario,
                        &evidence_by_id,
                    )?;
                }
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
        if let Some(terminal_fingerprints) = &self.terminal_fingerprints {
            validate_terminal_fingerprints(terminal_fingerprints)?;
        }

        let mut encoder = Encoder::new(maximum_bytes.min(MAX_PREPARED_SEMANTIC_RESULT_BYTES));
        let version = if self
            .finding
            .as_ref()
            .is_some_and(|finding| finding.triage_replays.is_some())
        {
            PreparedSemanticResultVersion::V5
        } else if self
            .finding
            .as_ref()
            .is_some_and(finding_has_incompatibility)
        {
            PreparedSemanticResultVersion::V4
        } else if self.terminal_fingerprints.is_some() {
            PreparedSemanticResultVersion::V3
        } else {
            PreparedSemanticResultVersion::V2
        };
        encoder.raw(version.magic())?;
        encode_observation(&mut encoder, &self.observation)?;
        encode_measurement_evidence(&mut encoder, &self.measurement_replay_evidence)?;
        match version {
            PreparedSemanticResultVersion::V4 | PreparedSemanticResultVersion::V5 => {
                match &self.terminal_fingerprints {
                    Some(terminal_fingerprints) => {
                        encoder.byte(1)?;
                        encode_terminal_fingerprints(&mut encoder, terminal_fingerprints)?;
                    }
                    None => encoder.byte(0)?,
                }
            }
            _ => {
                if let Some(terminal_fingerprints) = &self.terminal_fingerprints {
                    encode_terminal_fingerprints(&mut encoder, terminal_fingerprints)?;
                }
            }
        }
        match &self.finding {
            Some(finding) => {
                encoder.byte(1)?;
                encode_finding(&mut encoder, finding, version)?;
            }
            None => encoder.byte(0)?,
        }
        let bytes = encoder.finish()?;

        // Enforce the caller's operational byte ceiling before hashing raw
        // trace tables or reconstructing retained finding replay records.
        validate_measurement_evidence(
            &self.observation,
            &self.measurement_replay_evidence,
            self.finding.as_ref(),
        )?;
        if let Some(finding) = &self.finding {
            validate_finding(finding)?;
        }
        Ok(bytes)
    }

    /// Decodes and revalidates strict journal payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedSemanticResultCodecError`] for truncated, trailing,
    /// oversized, noncanonical, or semantically inconsistent bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PreparedSemanticResultCodecError> {
        Self::from_canonical_bytes_with_limit(bytes, MAX_PREPARED_SEMANTIC_RESULT_BYTES)
    }

    /// Decodes strict journal bytes under a caller-selected operational limit.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedSemanticResultCodecError`] for invalid input or when
    /// its length exceeds the smaller of `maximum_bytes` and the format ceiling.
    pub fn from_canonical_bytes_with_limit(
        bytes: &[u8],
        maximum_bytes: usize,
    ) -> Result<Self, PreparedSemanticResultCodecError> {
        let maximum_bytes = maximum_bytes.min(MAX_PREPARED_SEMANTIC_RESULT_BYTES);
        if bytes.len() > maximum_bytes {
            return Err(PreparedSemanticResultCodecError::LimitExceeded);
        }

        let version = PreparedSemanticResultVersion::from_payload(bytes)
            .unwrap_or(PreparedSemanticResultVersion::V2);
        let mut decoder = Decoder::new(bytes);
        decoder.magic(version.magic())?;
        let observation = decode_observation(&mut decoder)?;
        let measurement_replay_evidence = match version {
            PreparedSemanticResultVersion::V1 => Vec::new(),
            PreparedSemanticResultVersion::V2
            | PreparedSemanticResultVersion::V3
            | PreparedSemanticResultVersion::V4
            | PreparedSemanticResultVersion::V5 => decode_measurement_evidence(&mut decoder)?,
        };
        let terminal_fingerprints = match version {
            PreparedSemanticResultVersion::V1 | PreparedSemanticResultVersion::V2 => None,
            PreparedSemanticResultVersion::V3 => Some(decode_terminal_fingerprints(&mut decoder)?),
            PreparedSemanticResultVersion::V4 | PreparedSemanticResultVersion::V5 => {
                match decoder.byte()? {
                    0 => None,
                    1 => Some(decode_terminal_fingerprints(&mut decoder)?),
                    _ => return Err(PreparedSemanticResultCodecError::InvalidTag),
                }
            }
        };
        let finding = match decoder.byte()? {
            0 => None,
            1 => Some(decode_finding(&mut decoder, version)?),
            _ => return Err(PreparedSemanticResultCodecError::InvalidTag),
        };
        decoder.finish()?;

        let value = Self::new_with_measurement_replay_evidence(
            observation,
            measurement_replay_evidence,
            finding,
        )?;
        let value = match terminal_fingerprints {
            Some(terminal_fingerprints) => {
                value.with_terminal_fingerprints(terminal_fingerprints)?
            }
            None => value,
        };
        let canonical = match version {
            PreparedSemanticResultVersion::V1 => {
                value.canonical_v1_bytes_with_limit(maximum_bytes)?
            }
            PreparedSemanticResultVersion::V2
            | PreparedSemanticResultVersion::V3
            | PreparedSemanticResultVersion::V4
            | PreparedSemanticResultVersion::V5 => {
                value.canonical_bytes_with_limit(maximum_bytes)?
            }
        };
        if canonical != bytes {
            return Err(PreparedSemanticResultCodecError::NonCanonical);
        }
        Ok(value)
    }

    /// Consumes the durable result into its exact publication records.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ObservationCandidate,
        Vec<CrucibleMeasurementReplayEvidence>,
        Option<Vec<FingerprintSample>>,
        Option<PreparedCrucibleFindingCandidate>,
    ) {
        (
            self.observation,
            self.measurement_replay_evidence,
            self.terminal_fingerprints,
            self.finding,
        )
    }

    /// Returns the legacy v1 encoding for journal compatibility checks.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedSemanticResultCodecError`] when this result owns raw
    /// measurement evidence, is inconsistent, or exceeds `maximum_bytes`.
    pub(crate) fn canonical_v1_bytes_with_limit(
        &self,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, PreparedSemanticResultCodecError> {
        if !self.measurement_replay_evidence.is_empty() {
            return Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "v1 measurement replay evidence",
            });
        }
        if self.terminal_fingerprints.is_some() {
            return Err(inconsistent("v1 terminal fingerprint evidence"));
        }
        validate_pair(&self.observation, self.finding.as_ref())?;

        let mut encoder = Encoder::new(maximum_bytes.min(MAX_PREPARED_SEMANTIC_RESULT_BYTES));
        encoder.raw(PREPARED_RESULT_MAGIC_V1)?;
        encode_observation(&mut encoder, &self.observation)?;
        match &self.finding {
            Some(finding) => {
                encoder.byte(1)?;
                encode_finding(&mut encoder, finding, PreparedSemanticResultVersion::V1)?;
            }
            None => encoder.byte(0)?,
        }
        let bytes = encoder.finish()?;
        validate_measurement_evidence(&self.observation, &[], self.finding.as_ref())?;
        Ok(bytes)
    }
}

/// Declared prepared-result payload version used by local journal recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PreparedSemanticResultVersion {
    /// Legacy observation/finding closure without owned raw measurement leaves.
    V1,
    /// Closure with exact raw measurement replay-leaf ownership.
    V2,
    /// Closure with exact raw measurement and terminal-fingerprint evidence.
    V3,
    /// Closure with typed deterministic candidate incompatibility outcomes.
    V4,
    /// Closure with four role-specific native triage replay records.
    V5,
}

impl PreparedSemanticResultVersion {
    /// Detects the declared version of a complete prepared-result payload.
    pub(crate) fn from_payload(bytes: &[u8]) -> Option<Self> {
        if bytes.starts_with(PREPARED_RESULT_MAGIC_V1) {
            Some(Self::V1)
        } else if bytes.starts_with(PREPARED_RESULT_MAGIC_V2) {
            Some(Self::V2)
        } else if bytes.starts_with(PREPARED_RESULT_MAGIC_V3) {
            Some(Self::V3)
        } else if bytes.starts_with(PREPARED_RESULT_MAGIC_V4) {
            Some(Self::V4)
        } else if bytes.starts_with(PREPARED_RESULT_MAGIC_V5) {
            Some(Self::V5)
        } else {
            None
        }
    }

    const fn magic(self) -> &'static [u8] {
        match self {
            Self::V1 => PREPARED_RESULT_MAGIC_V1,
            Self::V2 => PREPARED_RESULT_MAGIC_V2,
            Self::V3 => PREPARED_RESULT_MAGIC_V3,
            Self::V4 => PREPARED_RESULT_MAGIC_V4,
            Self::V5 => PREPARED_RESULT_MAGIC_V5,
        }
    }

    const fn supports_replay_incompatibility(self) -> bool {
        matches!(self, Self::V4 | Self::V5)
    }
}

fn finding_has_incompatibility(finding: &PreparedCrucibleFindingCandidate) -> bool {
    finding
        .minimization_replays
        .iter()
        .chain(&finding.verification_replays)
        .any(|replay| replay.incompatibility().is_some())
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
}

fn validate_pair(
    observation: &ObservationCandidate,
    finding: Option<&PreparedCrucibleFindingCandidate>,
) -> Result<(), PreparedSemanticResultCodecError> {
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
        Some(FindingTarget::ChoiceOpportunity(target))
            if !observed.discovered_choices().contains(&target) =>
        {
            return Err(inconsistent("finding choice target"));
        }
        _ => {}
    }

    let mut owned = BTreeSet::from([
        observed.attempt().content_id(),
        child.content_id(),
        observed.path().content_id(),
        observed.measurements().content_id(),
        observed.properties().content_id(),
        observed.coverage().content_id(),
    ]);
    owned.extend(
        observed
            .discovered_choices()
            .iter()
            .map(|id| id.content_id()),
    );
    owned.extend(
        observed
            .produced_selections()
            .iter()
            .map(|id| id.content_id()),
    );
    if !signature.causal_evidence().is_subset(&owned) {
        return Err(inconsistent("finding causal evidence"));
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

fn validate_measurement_evidence(
    observation: &ObservationCandidate,
    evidence: &[CrucibleMeasurementReplayEvidence],
    finding: Option<&PreparedCrucibleFindingCandidate>,
) -> Result<(), PreparedSemanticResultCodecError> {
    let observation_requires_evidence =
        measurement_requires_replay_evidence(observation.measurements());
    let finding_requires_evidence = finding.is_some_and(|finding| {
        finding
            .replay_records
            .measurements
            .iter()
            .any(measurement_requires_replay_evidence)
    });
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
    validate_observation_stop_evidence(observation, &evidence_by_id)?;

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
        for measurement in &finding.replay_records.measurements {
            if measurement_requires_replay_evidence(measurement)
                && !referenced_measurements.contains(&measurement.id()?)
            {
                return Err(inconsistent(
                    "unreferenced finding replay measurement record",
                ));
            }
        }

        let configurations = finding
            .replay_records
            .configurations
            .iter()
            .map(|record| record.id().map(|id| (id, record)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let measurements = finding
            .replay_records
            .measurements
            .iter()
            .map(|record| record.id().map(|id| (id, record)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        for replay in finding
            .minimization_replays
            .iter()
            .chain(&finding.verification_replays)
        {
            let Some((measurement_id, _, _, _, _)) = replay.observed_components() else {
                continue;
            };
            let measurement = measurements
                .get(&measurement_id)
                .ok_or_else(|| inconsistent("finding replay measurement record"))?;
            if !measurement_requires_replay_evidence(measurement) {
                continue;
            }
            let configuration = configurations
                .get(&replay.configuration())
                .ok_or_else(|| inconsistent("finding replay measurement configuration"))?;
            validate_measurement_record(
                measurement,
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
    measurement.evaluation().is_some_and(|evaluation| {
        evaluation.payload_schema() == CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V2
    })
}

fn validate_observation_stop_evidence(
    candidate: &ObservationCandidate,
    evidence_by_id: &BTreeMap<
        crucible_cas::content_store::ContentId,
        &CrucibleMeasurementReplayEvidence,
    >,
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

    let evaluation = candidate
        .measurements()
        .evaluation()
        .ok_or_else(|| inconsistent("observation stop measurement evaluation"))?;
    if evaluation.payload_schema() != CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V2
        || evaluation.evidence().len() != 1
    {
        return Err(inconsistent("observation stop measurement evidence"));
    }
    let evidence_id = *evaluation
        .evidence()
        .first()
        .ok_or_else(|| inconsistent("observation stop measurement evidence"))?;
    let evidence = evidence_by_id
        .get(&evidence_id)
        .copied()
        .ok_or_else(|| inconsistent("observation stop measurement evidence"))?;
    if evidence.configuration() != proof.child() {
        return Err(inconsistent("observation stop configuration"));
    }

    let event_log = proof.event_log();
    let retained_boundary = evidence
        .observation_boundary()
        .ok_or_else(|| inconsistent("observation stop execution boundary"))?;
    let retained_offset = retained_boundary.event_log_offset();
    if retained_boundary.frontier().ticks != boundary.frontier_nanoseconds()
        || retained_boundary.quantum_start_completed_quanta() != boundary.start_completed_quanta()
        || retained_boundary.completed_quanta() != boundary.completed_quanta()
        || retained_boundary.quantum_start_events() != boundary.start_events()
        || CampaignHash::from_bytes(retained_offset.prefix.bytes) != event_log.prefix()
        || retained_offset
            .appended_segment
            .map(|hash| CampaignHash::from_bytes(hash.bytes))
            != event_log.appended_segment()
        || retained_offset.bytes != event_log.bytes()
        || retained_offset.events != event_log.events()
    {
        return Err(inconsistent("observation stop execution boundary"));
    }
    let event_count = usize::try_from(event_log.events())
        .map_err(|_| inconsistent("observation stop event count"))?;
    let quantum_start = usize::try_from(boundary.start_events())
        .map_err(|_| inconsistent("observation stop quantum event count"))?;
    let prefix = evidence
        .entries()
        .get(..event_count)
        .ok_or_else(|| inconsistent("observation stop event prefix"))?;
    if quantum_start > event_count
        || observation_event_prefix_digest(prefix) != event_log.digest()
        || prefix
            .iter()
            .any(|entry| entry.at().ticks > boundary.frontier_nanoseconds())
        || evidence.terminal().at.ticks < boundary.frontier_nanoseconds()
    {
        return Err(inconsistent("observation stop event prefix"));
    }

    match proof.condition() {
        ObservationCondition::SchedulerQuiescent => {
            if proof.satisfaction() != ObservationStopSatisfaction::SchedulerQuiescent
                || proof.assertion_witness().is_some()
                || !retained_boundary.scheduler_quiescent()
            {
                return Err(inconsistent("scheduler-quiescent observation stop"));
            }
        }
        ObservationCondition::AssertionViolationTransition(assertion) => {
            if proof.satisfaction() != ObservationStopSatisfaction::AssertionViolationTransition {
                return Err(inconsistent("assertion observation stop witness"));
            }
            let witness = proof
                .assertion_witness()
                .ok_or_else(|| inconsistent("assertion observation stop witness"))?;
            let entry = prefix
                .get(quantum_start..)
                .and_then(|entries| {
                    entries
                        .iter()
                        .find(|entry| entry.sequence() == witness.sequence())
                })
                .ok_or_else(|| inconsistent("assertion observation stop witness"))?;
            if CampaignHash::from_bytes(entry.content_hash().bytes) != witness.entry()
                || !matches!(
                    entry.payload(),
                    SchedulerEventLogPayload::Observable(
                        ObservableEventPayload::AssertionStateChanged { name, state }
                    ) if name.name == *assertion
                        && name.name == witness.assertion()
                        && *state == AssertionPhase::Violated
                )
            {
                return Err(inconsistent("assertion observation stop witness"));
            }
        }
        ObservationCondition::AnyAssertionViolationTransition => {
            if proof.satisfaction() != ObservationStopSatisfaction::AssertionViolationTransition {
                return Err(inconsistent("assertion observation stop witness"));
            }
            let witness = proof
                .assertion_witness()
                .ok_or_else(|| inconsistent("assertion observation stop witness"))?;
            let entry = prefix
                .get(quantum_start..)
                .and_then(|entries| {
                    entries
                        .iter()
                        .find(|entry| entry.sequence() == witness.sequence())
                })
                .ok_or_else(|| inconsistent("assertion observation stop witness"))?;
            if CampaignHash::from_bytes(entry.content_hash().bytes) != witness.entry()
                || !matches!(
                    entry.payload(),
                    SchedulerEventLogPayload::Observable(
                        ObservableEventPayload::AssertionStateChanged { name, state }
                    ) if name.name == witness.assertion()
                        && *state == AssertionPhase::Violated
                )
            {
                return Err(inconsistent("assertion observation stop witness"));
            }
        }
        ObservationCondition::SchedulerQuiescentOrExecutionQuanta { execution_quanta } => {
            let expected_satisfaction = if retained_boundary.scheduler_quiescent() {
                ObservationStopSatisfaction::SchedulerQuiescent
            } else if boundary.completed_quanta() >= *execution_quanta {
                ObservationStopSatisfaction::ExecutionQuanta
            } else {
                return Err(inconsistent("compound observation stop"));
            };
            if proof.satisfaction() != expected_satisfaction || proof.assertion_witness().is_some()
            {
                return Err(inconsistent("compound observation stop"));
            }
        }
    }
    Ok(())
}

fn observation_event_prefix_digest(entries: &[SchedulerEventLogEntry]) -> CampaignHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.savepoint-replay-event-prefix.v1\0");
    hasher.update(&(entries.len() as u64).to_be_bytes());
    for entry in entries {
        hasher.update(&entry.sequence().to_be_bytes());
        hasher.update(&entry.content_hash().bytes);
    }
    CampaignHash::from_bytes(*hasher.finalize().as_bytes())
}

fn verify_measurement_record(
    measurement: &MeasurementSet,
    configuration: crucible_campaign::ConfigurationId,
    expected_scenario: crucible_campaign::ScenarioDefId,
    scenario: &ScenarioDefForm,
    evidence_by_id: &BTreeMap<
        crucible_cas::content_store::ContentId,
        &CrucibleMeasurementReplayEvidence,
    >,
) -> Result<(), PreparedSemanticResultCodecError> {
    let Some(evaluation) = measurement.evaluation() else {
        return Ok(());
    };
    if evaluation.payload_schema() != CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V2 {
        return Ok(());
    }
    let evidence_id = evaluation
        .evidence()
        .first()
        .copied()
        .ok_or_else(|| inconsistent("measurement replay evidence edge"))?;
    let evidence = evidence_by_id
        .get(&evidence_id)
        .copied()
        .ok_or_else(|| inconsistent("missing measurement replay evidence"))?;

    verify_crucible_measurement_publication(
        measurement,
        evidence,
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
        crucible_cas::content_store::ContentId,
        &CrucibleMeasurementReplayEvidence,
    >,
    owned: &mut BTreeSet<crucible_cas::content_store::ContentId>,
) -> Result<(), PreparedSemanticResultCodecError> {
    let Some(evaluation) = measurement.evaluation() else {
        return Ok(());
    };
    if evaluation.payload_schema() != CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V2 {
        return Ok(());
    }
    if evaluation.evidence().len() != 1 {
        return Err(inconsistent("measurement replay evidence edge"));
    }
    let evidence_id = *evaluation
        .evidence()
        .first()
        .ok_or_else(|| inconsistent("measurement replay evidence edge"))?;
    let leaf = evidence_by_id
        .get(&evidence_id)
        .ok_or_else(|| inconsistent("missing measurement replay evidence"))?;
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

#[cfg(test)]
pub(super) fn encode_v1_without_measurement_evidence_for_test(
    observation: &ObservationCandidate,
    finding: Option<&PreparedCrucibleFindingCandidate>,
) -> Result<Vec<u8>, PreparedSemanticResultCodecError> {
    let mut encoder = Encoder::new(MAX_PREPARED_SEMANTIC_RESULT_BYTES);
    encoder.raw(PREPARED_RESULT_MAGIC_V1)?;
    encode_observation(&mut encoder, observation)?;
    match finding {
        Some(finding) => {
            encoder.byte(1)?;
            encode_finding(&mut encoder, finding, PreparedSemanticResultVersion::V1)?;
        }
        None => encoder.byte(0)?,
    }
    encoder.finish()
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

    ObservationCandidate::from_recorded_parts(
        child,
        measurements,
        properties,
        coverage,
        discoveries,
        selections,
        observation,
    )
    .map_err(Into::into)
}

fn encode_finding(
    encoder: &mut Encoder,
    value: &PreparedCrucibleFindingCandidate,
    version: PreparedSemanticResultVersion,
) -> Result<(), PreparedSemanticResultCodecError> {
    encoder.byte(discovery_path_tag(value.discovery_path))?;
    encoder.raw(&value.minimization_seed.bytes())?;
    encoder.record(&value.scenario.canonical_bytes())?;
    encoder.record(&value.original_configuration.canonical_bytes())?;
    encoder.record(&value.original.canonical_bytes())?;
    encoder.record(&value.minimized_configuration.canonical_bytes())?;
    encoder.record(&value.minimized.canonical_bytes())?;
    encode_records(
        encoder,
        &value.replay_records.configurations,
        ConfigurationArtifact::canonical_bytes,
    )?;
    encode_records(
        encoder,
        &value.replay_records.measurements,
        MeasurementSet::canonical_bytes,
    )?;
    encode_records(
        encoder,
        &value.replay_records.properties,
        PropertyVerdictSet::canonical_bytes,
    )?;
    encode_records(
        encoder,
        &value.replay_records.coverage,
        CoverageProjection::canonical_bytes,
    )?;
    encode_records(
        encoder,
        &value.replay_records.declarations,
        SelectableDeclaration::canonical_bytes,
    )?;
    encode_records(
        encoder,
        &value.replay_records.domains,
        ChoiceDomain::canonical_bytes,
    )?;
    encode_records(
        encoder,
        &value.replay_records.opportunities,
        ChoiceOpportunity::canonical_bytes,
    )?;
    encode_records(
        encoder,
        &value.replay_records.selections,
        Selection::canonical_bytes,
    )?;
    encode_replays(encoder, value, version)?;
    match (version, &value.triage_replays) {
        (PreparedSemanticResultVersion::V5, Some(triage_replays)) => {
            for replay in triage_replays.records() {
                encoder.record(&replay.canonical_bytes())?;
            }
        }
        (PreparedSemanticResultVersion::V5, None) => {
            return Err(inconsistent("v5 finding triage replay evidence"));
        }
        (_, Some(_)) => {
            return Err(inconsistent("legacy finding triage replay evidence"));
        }
        (_, None) => {}
    }
    encoder.record(&value.bundle.canonical_bytes())?;
    Ok(())
}

fn decode_finding(
    decoder: &mut Decoder<'_>,
    version: PreparedSemanticResultVersion,
) -> Result<PreparedCrucibleFindingCandidate, PreparedSemanticResultCodecError> {
    let discovery_path = discovery_path_from_tag(decoder.byte()?)?;
    let minimization_seed = crucible::Seed::from_bytes(
        decoder
            .take(32)?
            .try_into()
            .map_err(|_| PreparedSemanticResultCodecError::Truncated)?,
    );
    let scenario = decoder.decode_record(ScenarioArtifact::from_canonical_bytes)?;
    let original_configuration =
        decoder.decode_record(ConfigurationArtifact::from_canonical_bytes)?;
    let original = decoder.decode_record(ReproductionArtifact::from_canonical_bytes)?;
    let minimized_configuration =
        decoder.decode_record(ConfigurationArtifact::from_canonical_bytes)?;
    let minimized = decoder.decode_record(ReproductionArtifact::from_canonical_bytes)?;
    let mut replay_record_count = 0usize;
    let mut replay_record_bytes = 0usize;
    let configurations = decoder.decode_replay_records(
        ConfigurationArtifact::from_canonical_bytes,
        &mut replay_record_count,
        &mut replay_record_bytes,
    )?;
    let measurements = decoder.decode_replay_records(
        MeasurementSet::from_canonical_bytes,
        &mut replay_record_count,
        &mut replay_record_bytes,
    )?;
    let properties = decoder.decode_replay_records(
        PropertyVerdictSet::from_canonical_bytes,
        &mut replay_record_count,
        &mut replay_record_bytes,
    )?;
    let coverage = decoder.decode_replay_records(
        CoverageProjection::from_canonical_bytes,
        &mut replay_record_count,
        &mut replay_record_bytes,
    )?;
    let declarations = decoder.decode_replay_records(
        SelectableDeclaration::from_canonical_bytes,
        &mut replay_record_count,
        &mut replay_record_bytes,
    )?;
    let domains = decoder.decode_replay_records(
        ChoiceDomain::from_canonical_bytes,
        &mut replay_record_count,
        &mut replay_record_bytes,
    )?;
    let opportunities = decoder.decode_replay_records(
        ChoiceOpportunity::from_canonical_bytes,
        &mut replay_record_count,
        &mut replay_record_bytes,
    )?;
    let selections = decoder.decode_replay_records(
        Selection::from_canonical_bytes,
        &mut replay_record_count,
        &mut replay_record_bytes,
    )?;
    let mut replay_validation_references = 0usize;
    let minimization_indexes =
        decode_replay_indexes(decoder, &mut replay_validation_references, version)?;
    let verification_indexes =
        decode_replay_indexes(decoder, &mut replay_validation_references, version)?;
    let triage_replays = if version == PreparedSemanticResultVersion::V5 {
        Some(PreparedFindingTriageReplayRecords {
            minimization_original: decoder
                .decode_record(FindingTriageReplayEvidence::from_canonical_bytes)?,
            minimization_selected: decoder
                .decode_record(FindingTriageReplayEvidence::from_canonical_bytes)?,
            verification_original: decoder
                .decode_record(FindingTriageReplayEvidence::from_canonical_bytes)?,
            verification_selected: decoder
                .decode_record(FindingTriageReplayEvidence::from_canonical_bytes)?,
        })
    } else {
        None
    };
    let bundle = decoder.decode_record(FindingCandidateBundle::from_canonical_bytes)?;

    // Resolve every content identity once. Compact replay indexes can refer to
    // the same large record many times, so hashing on every reference would
    // perform work far beyond the encoded input bound.
    let configuration_ids = record_ids(&configurations, ConfigurationArtifact::id)?;
    let measurement_ids = record_ids(&measurements, MeasurementSet::id)?;
    let property_ids = record_ids(&properties, PropertyVerdictSet::id)?;
    let coverage_ids = record_ids(&coverage, CoverageProjection::id)?;
    let opportunity_ids = record_ids(&opportunities, ChoiceOpportunity::id)?;
    let selection_ids = record_ids(&selections, Selection::id)?;

    let minimization_replays = materialize_replays(
        &minimization_indexes,
        bundle.signature_minimization().minimization_pass(),
        &configuration_ids,
        &measurement_ids,
        &property_ids,
        &coverage_ids,
        &opportunity_ids,
        &selection_ids,
    )?;
    let verification_replays = materialize_replays(
        &verification_indexes,
        bundle.signature_minimization().verification_pass(),
        &configuration_ids,
        &measurement_ids,
        &property_ids,
        &coverage_ids,
        &opportunity_ids,
        &selection_ids,
    )?;

    let (record_count, canonical_bytes) = replay_record_totals(
        &configurations,
        &measurements,
        &properties,
        &coverage,
        &declarations,
        &domains,
        &opportunities,
        &selections,
        &bundle,
    )?;
    let replay_records = PreparedFindingReplayRecords {
        configurations,
        measurements,
        properties,
        coverage,
        declarations,
        domains,
        opportunities,
        selections,
        record_count,
        canonical_bytes,
    };
    let value = PreparedCrucibleFindingCandidate {
        discovery_path,
        minimization_seed,
        scenario,
        original_configuration,
        original,
        minimized_configuration,
        minimized,
        replay_records,
        minimization_replays,
        verification_replays,
        triage_replays,
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
        value.discovery_path,
        "journal minimized finding reproduction",
    )?;
    validate_finding_triage_replays(value, &original_finding, &minimized_finding)?;
    Ok(())
}

fn decode_journal_finding_reproduction(
    reproduction: &ReproductionArtifact,
    discovery_path: crucible::FindingDiscoveryPath,
    artifact_name: &'static str,
) -> Result<FindingReproductionArtifact, PreparedSemanticResultCodecError> {
    let artifact = crucible::ReproductionArtifact::from_compact_binary(reproduction.payload())
        .map_err(|source| CrucibleArtifactError::InvalidPayload {
            artifact: artifact_name,
            source: Box::new(source),
        })?;
    let replay = artifact
        .replay()
        .map_err(|source| CrucibleArtifactError::InvalidPayload {
            artifact: artifact_name,
            source: Box::new(source),
        })?;
    let configuration = crucible::Configuration {
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
        let native_replay =
            FailureTriageReplayEvidence::from_compact_binary(finding.clone(), record.payload())
                .map_err(|source| CrucibleArtifactError::InvalidPayload {
                    artifact: "journal finding triage replay evidence",
                    source: Box::new(source),
                })?;
        if record.payload_schema() != native_replay.schema_version() {
            return Err(inconsistent(
                "finding triage replay declared payload schema",
            ));
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
    }
    Ok(())
}

fn validate_recorded_replays(
    value: &PreparedCrucibleFindingCandidate,
) -> Result<(), PreparedSemanticResultCodecError> {
    let configurations = indexed_by_id(
        &value.replay_records.configurations,
        |record| record.id(),
        ConfigurationArtifact::canonical_bytes,
    )?;
    let measurements = indexed_by_id(
        &value.replay_records.measurements,
        |record| record.id(),
        MeasurementSet::canonical_bytes,
    )?;
    let properties = indexed_by_id(
        &value.replay_records.properties,
        |record| record.id(),
        PropertyVerdictSet::canonical_bytes,
    )?;
    let coverage = indexed_by_id(
        &value.replay_records.coverage,
        |record| record.id(),
        CoverageProjection::canonical_bytes,
    )?;
    let declarations = indexed_by_id(
        &value.replay_records.declarations,
        |record| record.id(),
        SelectableDeclaration::canonical_bytes,
    )?;
    let domains = indexed_by_id(
        &value.replay_records.domains,
        |record| record.id(),
        ChoiceDomain::canonical_bytes,
    )?;
    let opportunities = indexed_by_id(
        &value.replay_records.opportunities,
        |record| record.id(),
        ChoiceOpportunity::canonical_bytes,
    )?;
    let selections = indexed_by_id(
        &value.replay_records.selections,
        |record| record.id(),
        Selection::canonical_bytes,
    )?;

    // A compact journal may refer to one large record from every replay. Bound
    // that repeated copy work before reconstructing any owned evidence values.
    let mut referenced_bytes = 0usize;
    let mut reference_count = 0usize;
    for replay in value
        .minimization_replays
        .iter()
        .chain(&value.verification_replays)
    {
        charge_reference(
            &configurations,
            &replay.configuration(),
            &mut referenced_bytes,
            &mut reference_count,
            "finding replay configuration",
        )?;
        let Some((measurement_id, property_id, coverage_id, opportunity_ids, selection_ids)) =
            replay.observed_components()
        else {
            continue;
        };
        charge_reference(
            &measurements,
            &measurement_id,
            &mut referenced_bytes,
            &mut reference_count,
            "finding replay measurements",
        )?;
        charge_reference(
            &properties,
            &property_id,
            &mut referenced_bytes,
            &mut reference_count,
            "finding replay properties",
        )?;
        charge_reference(
            &coverage,
            &coverage_id,
            &mut referenced_bytes,
            &mut reference_count,
            "finding replay coverage",
        )?;
        for opportunity_id in opportunity_ids {
            let (opportunity, _) = charge_reference(
                &opportunities,
                opportunity_id,
                &mut referenced_bytes,
                &mut reference_count,
                "finding replay opportunity",
            )?;
            charge_reference(
                &declarations,
                &opportunity.declaration(),
                &mut referenced_bytes,
                &mut reference_count,
                "finding replay declaration",
            )?;
            charge_reference(
                &domains,
                &opportunity.domain(),
                &mut referenced_bytes,
                &mut reference_count,
                "finding replay domain",
            )?;
        }
        for selection_id in selection_ids {
            charge_reference(
                &selections,
                selection_id,
                &mut referenced_bytes,
                &mut reference_count,
                "finding replay selection",
            )?;
        }
    }

    for replay in value
        .minimization_replays
        .iter()
        .chain(&value.verification_replays)
    {
        let (configuration, _) = configurations.get(&replay.configuration()).ok_or(
            PreparedSemanticResultCodecError::Inconsistent {
                component: "finding replay configuration",
            },
        )?;
        let Some((measurement_id, property_id, coverage_id, opportunity_ids, selection_ids)) =
            replay.observed_components()
        else {
            continue;
        };
        let (measurement, _) = measurements.get(&measurement_id).ok_or(
            PreparedSemanticResultCodecError::Inconsistent {
                component: "finding replay measurements",
            },
        )?;
        let (property, _) =
            properties
                .get(&property_id)
                .ok_or(PreparedSemanticResultCodecError::Inconsistent {
                    component: "finding replay properties",
                })?;
        let (projection, _) =
            coverage
                .get(&coverage_id)
                .ok_or(PreparedSemanticResultCodecError::Inconsistent {
                    component: "finding replay coverage",
                })?;
        let mut discoveries = Vec::with_capacity(opportunity_ids.len());
        for opportunity_id in opportunity_ids {
            let (opportunity, _) = opportunities.get(opportunity_id).ok_or(
                PreparedSemanticResultCodecError::Inconsistent {
                    component: "finding replay opportunity",
                },
            )?;
            let (declaration, _) = declarations.get(&opportunity.declaration()).ok_or(
                PreparedSemanticResultCodecError::Inconsistent {
                    component: "finding replay declaration",
                },
            )?;
            let (domain, _) = domains.get(&opportunity.domain()).ok_or(
                PreparedSemanticResultCodecError::Inconsistent {
                    component: "finding replay domain",
                },
            )?;
            discoveries.push(ChoiceDiscovery::new(
                (*declaration).clone(),
                (*domain).clone(),
                (*opportunity).clone(),
            )?);
        }
        let replay_selections = selection_ids
            .iter()
            .map(|id| {
                selections
                    .get(id)
                    .map(|(record, _)| (*record).clone())
                    .ok_or(PreparedSemanticResultCodecError::Inconsistent {
                        component: "finding replay selection",
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let reconstructed = super::CrucibleFindingReplayEvidence::new(
            replay.signature().cloned(),
            (*configuration).clone(),
            (*measurement).clone(),
            (*property).clone(),
            (*projection).clone(),
            discoveries,
            replay_selections,
        )?;
        if reconstructed.configuration().id()? != replay.configuration()
            || reconstructed.signature() != replay.signature()
        {
            return Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "finding replay reconstruction",
            });
        }
    }
    Ok(())
}

fn indexed_by_id<T, I: Ord>(
    records: &[T],
    mut id: impl FnMut(&T) -> Result<I, CampaignCodecError>,
    canonical_bytes: impl Fn(&T) -> Vec<u8>,
) -> Result<BTreeMap<I, (&T, usize)>, PreparedSemanticResultCodecError> {
    let mut indexed = BTreeMap::new();
    for record in records {
        if indexed
            .insert(id(record)?, (record, canonical_bytes(record).len()))
            .is_some()
        {
            return Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "duplicate finding replay record",
            });
        }
    }
    Ok(indexed)
}

fn charge_reference<'a, T, I: Ord>(
    records: &'a BTreeMap<I, (&'a T, usize)>,
    id: &I,
    referenced_bytes: &mut usize,
    reference_count: &mut usize,
    component: &'static str,
) -> Result<(&'a T, usize), PreparedSemanticResultCodecError> {
    let &(record, bytes) = records
        .get(id)
        .ok_or(PreparedSemanticResultCodecError::Inconsistent { component })?;
    *reference_count = reference_count
        .checked_add(1)
        .ok_or(PreparedSemanticResultCodecError::LimitExceeded)?;
    *referenced_bytes = referenced_bytes
        .checked_add(bytes)
        .ok_or(PreparedSemanticResultCodecError::LimitExceeded)?;
    if *reference_count > MAX_REPLAY_VALIDATION_REFERENCES
        || *referenced_bytes > MAX_CRUCIBLE_FINDING_REPLAY_BYTES
    {
        return Err(PreparedSemanticResultCodecError::LimitExceeded);
    }
    Ok((record, bytes))
}

fn encode_replays(
    encoder: &mut Encoder,
    value: &PreparedCrucibleFindingCandidate,
    version: PreparedSemanticResultVersion,
) -> Result<(), PreparedSemanticResultCodecError> {
    let records = &value.replay_records;
    let configurations = content_positions(&records.configurations, |record| record.id())?;
    let measurements = content_positions(&records.measurements, |record| record.id())?;
    let properties = content_positions(&records.properties, |record| record.id())?;
    let coverage = content_positions(&records.coverage, |record| record.id())?;
    let opportunities = content_positions(&records.opportunities, |record| record.id())?;
    let selections = content_positions(&records.selections, |record| record.id())?;
    let indexes = ReplayRecordIndexes {
        configurations,
        measurements,
        properties,
        coverage,
        opportunities,
        selections,
    };
    encode_replay_pass(encoder, &value.minimization_replays, &indexes, version)?;
    encode_replay_pass(encoder, &value.verification_replays, &indexes, version)
}

fn content_positions<T, I>(
    records: &[T],
    mut id: impl FnMut(&T) -> Result<I, CampaignCodecError>,
) -> Result<BTreeMap<crucible_cas::content_store::ContentId, usize>, PreparedSemanticResultCodecError>
where
    I: ContentIdentity,
{
    let mut positions = BTreeMap::new();
    for (index, record) in records.iter().enumerate() {
        if positions.insert(id(record)?.content_id(), index).is_some() {
            return Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "duplicate finding replay record",
            });
        }
    }
    Ok(positions)
}

trait ContentIdentity {
    fn content_id(self) -> crucible_cas::content_store::ContentId;
}

macro_rules! content_identity {
    ($($type:ty),+ $(,)?) => {$(
        impl ContentIdentity for $type {
            fn content_id(self) -> crucible_cas::content_store::ContentId {
                self.content_id()
            }
        }
    )+};
}

content_identity!(
    crucible_campaign::ConfigurationArtifactId,
    crucible_campaign::MeasurementSetId,
    crucible_campaign::PropertyVerdictSetId,
    crucible_campaign::CoverageProjectionId,
    crucible_campaign::ChoiceOpportunityId,
    crucible_campaign::SelectionId,
);

struct ReplayRecordIndexes {
    configurations: BTreeMap<crucible_cas::content_store::ContentId, usize>,
    measurements: BTreeMap<crucible_cas::content_store::ContentId, usize>,
    properties: BTreeMap<crucible_cas::content_store::ContentId, usize>,
    coverage: BTreeMap<crucible_cas::content_store::ContentId, usize>,
    opportunities: BTreeMap<crucible_cas::content_store::ContentId, usize>,
    selections: BTreeMap<crucible_cas::content_store::ContentId, usize>,
}

fn encode_replay_pass(
    encoder: &mut Encoder,
    replays: &[RecordedFindingReplay],
    indexes: &ReplayRecordIndexes,
    version: PreparedSemanticResultVersion,
) -> Result<(), PreparedSemanticResultCodecError> {
    encoder.count(replays.len())?;
    for replay in replays {
        if version.supports_replay_incompatibility() {
            encoder.byte(if replay.incompatibility().is_some() {
                1
            } else {
                0
            })?;
        } else if replay.incompatibility().is_some() {
            return Err(inconsistent("legacy finding replay incompatibility"));
        }
        encoder.index(find_index(
            &indexes.configurations,
            replay.configuration().content_id(),
        )?)?;
        if let Some(reason) = replay.incompatibility() {
            encoder.byte(incompatibility_tag(reason))?;
            continue;
        }
        let Some((measurements, properties, coverage, opportunities, selections)) =
            replay.observed_components()
        else {
            return Err(inconsistent("finding replay outcome"));
        };
        encoder.index(find_index(
            &indexes.measurements,
            measurements.content_id(),
        )?)?;
        encoder.index(find_index(&indexes.properties, properties.content_id())?)?;
        encoder.index(find_index(&indexes.coverage, coverage.content_id())?)?;
        encoder.count(opportunities.len())?;
        for opportunity in opportunities {
            encoder.index(find_index(
                &indexes.opportunities,
                opportunity.content_id(),
            )?)?;
        }
        encoder.count(selections.len())?;
        for selection in selections {
            encoder.index(find_index(&indexes.selections, selection.content_id())?)?;
        }
    }
    Ok(())
}

fn find_index(
    indexes: &BTreeMap<crucible_cas::content_store::ContentId, usize>,
    id: crucible_cas::content_store::ContentId,
) -> Result<usize, PreparedSemanticResultCodecError> {
    indexes
        .get(&id)
        .copied()
        .ok_or(PreparedSemanticResultCodecError::Inconsistent {
            component: "finding replay record index",
        })
}

#[derive(Clone, Debug)]
enum ReplayIndexes {
    Observed {
        configuration: usize,
        measurements: usize,
        properties: usize,
        coverage: usize,
        opportunities: Vec<usize>,
        selections: Vec<usize>,
    },
    DeterministicallyIncompatible {
        configuration: usize,
        reason: FindingReplayIncompatibility,
    },
}

fn decode_replay_indexes(
    decoder: &mut Decoder<'_>,
    validation_references: &mut usize,
    version: PreparedSemanticResultVersion,
) -> Result<Vec<ReplayIndexes>, PreparedSemanticResultCodecError> {
    let count = decoder.count_bounded(MAX_CRUCIBLE_FINDING_REPLAY_RECORDS)?;
    charge_validation_references(validation_references, count, 4)?;
    let minimum_entry_bytes = if version.supports_replay_incompatibility() {
        // tag + configuration index + closed incompatibility reason
        2 + size_of::<u32>()
    } else {
        6 * size_of::<u32>()
    };
    decoder.preflight_collection(count, minimum_entry_bytes)?;
    let mut replays = Vec::with_capacity(count);
    for _ in 0..count {
        let incompatible = if version.supports_replay_incompatibility() {
            match decoder.byte()? {
                0 => false,
                1 => true,
                _ => return Err(PreparedSemanticResultCodecError::InvalidTag),
            }
        } else {
            false
        };
        let configuration = decoder.index()?;
        if incompatible {
            replays.push(ReplayIndexes::DeterministicallyIncompatible {
                configuration,
                reason: incompatibility_from_tag(decoder.byte()?)?,
            });
            continue;
        }
        let measurements = decoder.index()?;
        let properties = decoder.index()?;
        let coverage = decoder.index()?;
        let opportunity_count = decoder.count_bounded(MAX_CRUCIBLE_FINDING_REPLAY_RECORDS)?;
        charge_validation_references(validation_references, opportunity_count, 3)?;
        decoder.preflight_collection(opportunity_count, size_of::<u32>())?;
        let mut opportunities = Vec::with_capacity(opportunity_count);
        for _ in 0..opportunity_count {
            opportunities.push(decoder.index()?);
        }
        let selection_count = decoder.count_bounded(MAX_CRUCIBLE_FINDING_REPLAY_RECORDS)?;
        charge_validation_references(validation_references, selection_count, 1)?;
        decoder.preflight_collection(selection_count, size_of::<u32>())?;
        let mut selections = Vec::with_capacity(selection_count);
        for _ in 0..selection_count {
            selections.push(decoder.index()?);
        }
        replays.push(ReplayIndexes::Observed {
            configuration,
            measurements,
            properties,
            coverage,
            opportunities,
            selections,
        });
    }
    Ok(replays)
}

const fn incompatibility_tag(reason: FindingReplayIncompatibility) -> u8 {
    match reason {
        FindingReplayIncompatibility::PrefixDiverged => 0,
        FindingReplayIncompatibility::PrefixTerminated => 1,
        FindingReplayIncompatibility::SelectionMismatch => 2,
    }
}

fn incompatibility_from_tag(
    tag: u8,
) -> Result<FindingReplayIncompatibility, PreparedSemanticResultCodecError> {
    match tag {
        0 => Ok(FindingReplayIncompatibility::PrefixDiverged),
        1 => Ok(FindingReplayIncompatibility::PrefixTerminated),
        2 => Ok(FindingReplayIncompatibility::SelectionMismatch),
        _ => Err(PreparedSemanticResultCodecError::InvalidTag),
    }
}

fn charge_validation_references(
    current: &mut usize,
    records: usize,
    references_per_record: usize,
) -> Result<(), PreparedSemanticResultCodecError> {
    *current = records
        .checked_mul(references_per_record)
        .and_then(|additional| current.checked_add(additional))
        .ok_or(PreparedSemanticResultCodecError::LimitExceeded)?;
    if *current > MAX_REPLAY_VALIDATION_REFERENCES {
        return Err(PreparedSemanticResultCodecError::LimitExceeded);
    }
    Ok(())
}

// crucible-lint: allow rust-allow -- replay materialization receives parallel authenticated component tables.
#[allow(clippy::too_many_arguments)]
fn materialize_replays(
    indexes: &[ReplayIndexes],
    signatures: &[Option<crucible_campaign::FindingSignature>],
    configurations: &[crucible_campaign::ConfigurationArtifactId],
    measurements: &[crucible_campaign::MeasurementSetId],
    properties: &[crucible_campaign::PropertyVerdictSetId],
    coverage: &[crucible_campaign::CoverageProjectionId],
    opportunities: &[crucible_campaign::ChoiceOpportunityId],
    selections: &[crucible_campaign::SelectionId],
) -> Result<Vec<RecordedFindingReplay>, PreparedSemanticResultCodecError> {
    if indexes.len() != signatures.len() {
        return Err(PreparedSemanticResultCodecError::Inconsistent {
            component: "finding replay signature count",
        });
    }
    indexes
        .iter()
        .zip(signatures)
        .map(|(indexes, signature)| match indexes {
            ReplayIndexes::Observed {
                configuration,
                measurements: measurement,
                properties: property,
                coverage: projection,
                opportunities: opportunity_indexes,
                selections: selection_indexes,
            } => Ok(RecordedFindingReplay::Observed {
                signature: signature.clone().map(Box::new),
                configuration: *indexed(configurations, *configuration)?,
                measurements: *indexed(measurements, *measurement)?,
                properties: *indexed(properties, *property)?,
                coverage: *indexed(coverage, *projection)?,
                opportunities: opportunity_indexes
                    .iter()
                    .map(|index| indexed(opportunities, *index).copied())
                    .collect::<Result<Vec<_>, PreparedSemanticResultCodecError>>()?,
                selections: selection_indexes
                    .iter()
                    .map(|index| indexed(selections, *index).copied())
                    .collect::<Result<Vec<_>, PreparedSemanticResultCodecError>>()?,
            }),
            ReplayIndexes::DeterministicallyIncompatible {
                configuration,
                reason,
            } => {
                if signature.is_some() {
                    return Err(inconsistent("incompatible replay signature"));
                }
                Ok(RecordedFindingReplay::DeterministicallyIncompatible {
                    configuration: *indexed(configurations, *configuration)?,
                    reason: *reason,
                })
            }
        })
        .collect()
}

fn record_ids<T, I>(
    records: &[T],
    mut id: impl FnMut(&T) -> Result<I, CampaignCodecError>,
) -> Result<Vec<I>, PreparedSemanticResultCodecError> {
    records
        .iter()
        .map(|record| id(record).map_err(Into::into))
        .collect()
}

fn indexed<T>(records: &[T], index: usize) -> Result<&T, PreparedSemanticResultCodecError> {
    records
        .get(index)
        .ok_or(PreparedSemanticResultCodecError::Inconsistent {
            component: "finding replay record index",
        })
}

const fn discovery_path_tag(path: crucible::FindingDiscoveryPath) -> u8 {
    match path {
        crucible::FindingDiscoveryPath::InteractiveFork => 0,
        crucible::FindingDiscoveryPath::StateSpaceSearch => 1,
        crucible::FindingDiscoveryPath::CoverageGuidedFuzzing => 2,
        crucible::FindingDiscoveryPath::RetainedCorpusEntry => 3,
    }
}

fn discovery_path_from_tag(
    tag: u8,
) -> Result<crucible::FindingDiscoveryPath, PreparedSemanticResultCodecError> {
    match tag {
        0 => Ok(crucible::FindingDiscoveryPath::InteractiveFork),
        1 => Ok(crucible::FindingDiscoveryPath::StateSpaceSearch),
        2 => Ok(crucible::FindingDiscoveryPath::CoverageGuidedFuzzing),
        3 => Ok(crucible::FindingDiscoveryPath::RetainedCorpusEntry),
        _ => Err(PreparedSemanticResultCodecError::InvalidTag),
    }
}

// crucible-lint: allow rust-allow -- replay totals validate every bounded component table together.
#[allow(clippy::too_many_arguments)]
fn replay_record_totals(
    configurations: &[ConfigurationArtifact],
    measurements: &[MeasurementSet],
    properties: &[PropertyVerdictSet],
    coverage: &[CoverageProjection],
    declarations: &[SelectableDeclaration],
    domains: &[ChoiceDomain],
    opportunities: &[ChoiceOpportunity],
    selections: &[Selection],
    bundle: &FindingCandidateBundle,
) -> Result<(usize, usize), PreparedSemanticResultCodecError> {
    let mut identities = BTreeSet::new();
    let mut bytes = 0usize;
    macro_rules! charge {
        ($records:expr, $id:ident) => {
            for record in $records {
                if !identities.insert(record.$id()?.content_id()) {
                    return Err(PreparedSemanticResultCodecError::Inconsistent {
                        component: "duplicate finding replay record",
                    });
                }
                bytes = bytes
                    .checked_add(record.canonical_bytes().len())
                    .ok_or(PreparedSemanticResultCodecError::LimitExceeded)?;
            }
        };
    }
    charge!(configurations, id);
    charge!(measurements, id);
    charge!(properties, id);
    charge!(coverage, id);
    charge!(declarations, id);
    charge!(domains, id);
    charge!(opportunities, id);
    charge!(selections, id);
    for signature in bundle
        .signature_minimization()
        .minimization_pass()
        .iter()
        .chain(bundle.signature_minimization().verification_pass().iter())
        .flatten()
    {
        bytes = bytes
            .checked_add(signature.canonical_bytes().len())
            .ok_or(PreparedSemanticResultCodecError::LimitExceeded)?;
    }
    if identities.len() > MAX_CRUCIBLE_FINDING_REPLAY_RECORDS
        || bytes > MAX_CRUCIBLE_FINDING_REPLAY_BYTES
    {
        return Err(PreparedSemanticResultCodecError::LimitExceeded);
    }
    Ok((identities.len(), bytes))
}

fn encode_records<T>(
    encoder: &mut Encoder,
    records: &[T],
    encode: fn(&T) -> Vec<u8>,
) -> Result<(), PreparedSemanticResultCodecError> {
    encoder.count(records.len())?;
    for record in records {
        encoder.record(&encode(record))?;
    }
    Ok(())
}

struct Encoder {
    bytes: Vec<u8>,
    records: usize,
    maximum_bytes: usize,
}

impl Encoder {
    fn new(maximum_bytes: usize) -> Self {
        Self {
            bytes: Vec::new(),
            records: 0,
            maximum_bytes,
        }
    }

    fn finish(self) -> Result<Vec<u8>, PreparedSemanticResultCodecError> {
        if self.bytes.len() > self.maximum_bytes {
            Err(PreparedSemanticResultCodecError::LimitExceeded)
        } else {
            Ok(self.bytes)
        }
    }

    fn raw(&mut self, bytes: &[u8]) -> Result<(), PreparedSemanticResultCodecError> {
        self.reserve(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn byte(&mut self, value: u8) -> Result<(), PreparedSemanticResultCodecError> {
        self.raw(&[value])
    }

    fn count(&mut self, count: usize) -> Result<(), PreparedSemanticResultCodecError> {
        let count =
            u32::try_from(count).map_err(|_| PreparedSemanticResultCodecError::LimitExceeded)?;
        self.raw(&count.to_be_bytes())
    }

    fn index(&mut self, index: usize) -> Result<(), PreparedSemanticResultCodecError> {
        let index =
            u32::try_from(index).map_err(|_| PreparedSemanticResultCodecError::LimitExceeded)?;
        self.raw(&index.to_be_bytes())
    }

    fn record(&mut self, record: &[u8]) -> Result<(), PreparedSemanticResultCodecError> {
        if record.len() > MAX_RECORD_BYTES || self.records == MAX_PREPARED_RESULT_RECORDS {
            return Err(PreparedSemanticResultCodecError::LimitExceeded);
        }
        self.records += 1;
        let length = u32::try_from(record.len())
            .map_err(|_| PreparedSemanticResultCodecError::LimitExceeded)?;
        self.raw(&length.to_be_bytes())?;
        self.raw(record)
    }

    fn reserve(&mut self, additional: usize) -> Result<(), PreparedSemanticResultCodecError> {
        if self
            .bytes
            .len()
            .checked_add(additional)
            .is_none_or(|length| length > self.maximum_bytes)
        {
            return Err(PreparedSemanticResultCodecError::LimitExceeded);
        }
        self.bytes.reserve(additional);
        Ok(())
    }
}

struct Decoder<'a> {
    remaining: &'a [u8],
    records: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self {
            remaining: bytes,
            records: 0,
        }
    }

    fn finish(self) -> Result<(), PreparedSemanticResultCodecError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(PreparedSemanticResultCodecError::TrailingBytes)
        }
    }

    fn magic(&mut self, expected: &[u8]) -> Result<(), PreparedSemanticResultCodecError> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(PreparedSemanticResultCodecError::NonCanonical)
        }
    }

    fn byte(&mut self) -> Result<u8, PreparedSemanticResultCodecError> {
        Ok(self.take(1)?[0])
    }

    fn count(&mut self) -> Result<usize, PreparedSemanticResultCodecError> {
        let count = u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| PreparedSemanticResultCodecError::Truncated)?,
        ) as usize;
        if count > MAX_PREPARED_RESULT_RECORDS.saturating_sub(self.records) {
            return Err(PreparedSemanticResultCodecError::LimitExceeded);
        }
        Ok(count)
    }

    fn count_bounded(&mut self, maximum: usize) -> Result<usize, PreparedSemanticResultCodecError> {
        let count = self.count()?;
        if count > maximum {
            return Err(PreparedSemanticResultCodecError::LimitExceeded);
        }
        Ok(count)
    }

    fn index(&mut self) -> Result<usize, PreparedSemanticResultCodecError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| PreparedSemanticResultCodecError::Truncated)?,
        ) as usize)
    }

    fn record(&mut self) -> Result<&'a [u8], PreparedSemanticResultCodecError> {
        if self.records == MAX_PREPARED_RESULT_RECORDS {
            return Err(PreparedSemanticResultCodecError::LimitExceeded);
        }
        self.records += 1;
        let length = u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| PreparedSemanticResultCodecError::Truncated)?,
        ) as usize;
        if length > MAX_RECORD_BYTES {
            return Err(PreparedSemanticResultCodecError::LimitExceeded);
        }
        self.take(length)
    }

    fn decode_record<T>(
        &mut self,
        decode: fn(&[u8]) -> Result<T, CampaignCodecError>,
    ) -> Result<T, PreparedSemanticResultCodecError> {
        decode(self.record()?).map_err(Into::into)
    }

    fn decode_replay_records<T>(
        &mut self,
        decode: fn(&[u8]) -> Result<T, CampaignCodecError>,
        aggregate_count: &mut usize,
        aggregate_bytes: &mut usize,
    ) -> Result<Vec<T>, PreparedSemanticResultCodecError> {
        let remaining = MAX_CRUCIBLE_FINDING_REPLAY_RECORDS
            .checked_sub(*aggregate_count)
            .ok_or(PreparedSemanticResultCodecError::LimitExceeded)?;
        let count = self.count_bounded(remaining)?;
        *aggregate_count += count;
        self.preflight_collection(count, size_of::<u32>())?;

        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let bytes = self.record()?;
            *aggregate_bytes = aggregate_bytes
                .checked_add(bytes.len())
                .ok_or(PreparedSemanticResultCodecError::LimitExceeded)?;
            if *aggregate_bytes > MAX_CRUCIBLE_FINDING_REPLAY_BYTES {
                return Err(PreparedSemanticResultCodecError::LimitExceeded);
            }
            records.push(decode(bytes)?);
        }
        Ok(records)
    }

    fn preflight_collection(
        &self,
        count: usize,
        minimum_entry_bytes: usize,
    ) -> Result<(), PreparedSemanticResultCodecError> {
        let minimum_bytes = count
            .checked_mul(minimum_entry_bytes)
            .ok_or(PreparedSemanticResultCodecError::LimitExceeded)?;
        if minimum_bytes > self.remaining.len() {
            return Err(PreparedSemanticResultCodecError::Truncated);
        }
        Ok(())
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PreparedSemanticResultCodecError> {
        if self.remaining.len() < length {
            return Err(PreparedSemanticResultCodecError::Truncated);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- malformed index fixtures must fail the focused codec test.
#[allow(clippy::expect_used)]
mod v4_replay_index_tests {
    use super::*;
    use crucible::Schedule;

    const INCOMPATIBLE_REPLAYS: usize = 4_096;

    fn dense_incompatible_bytes() -> Vec<u8> {
        let scenario = crucible::happy_path_scenario()
            .expect("happy-path scenario")
            .scenario;
        let scenario =
            super::super::encode_crucible_scenario_artifact(&scenario).expect("scenario artifact");
        let configuration =
            super::super::encode_crucible_configuration_artifact(&scenario, &Schedule::empty())
                .expect("configuration artifact");
        let configuration_id = configuration.id().expect("configuration ID");
        let replays = (0..INCOMPATIBLE_REPLAYS)
            .map(|_| RecordedFindingReplay::DeterministicallyIncompatible {
                configuration: configuration_id,
                reason: FindingReplayIncompatibility::PrefixDiverged,
            })
            .collect::<Vec<_>>();
        let indexes = ReplayRecordIndexes {
            configurations: BTreeMap::from([(configuration_id.content_id(), 0)]),
            measurements: BTreeMap::new(),
            properties: BTreeMap::new(),
            coverage: BTreeMap::new(),
            opportunities: BTreeMap::new(),
            selections: BTreeMap::new(),
        };
        let mut encoder = Encoder::new(MAX_PREPARED_SEMANTIC_RESULT_BYTES);
        encode_replay_pass(
            &mut encoder,
            &replays,
            &indexes,
            PreparedSemanticResultVersion::V4,
        )
        .expect("encode dense incompatible pass");
        encoder.finish().expect("finish dense incompatible pass")
    }

    #[test]
    fn dense_incompatible_v4_pass_round_trips_without_legacy_padding() {
        let bytes = dense_incompatible_bytes();
        assert_eq!(bytes.len(), size_of::<u32>() + (INCOMPATIBLE_REPLAYS * 6));

        let mut decoder = Decoder::new(&bytes);
        let mut validation_references = 0;
        let decoded = decode_replay_indexes(
            &mut decoder,
            &mut validation_references,
            PreparedSemanticResultVersion::V4,
        )
        .expect("decode dense incompatible pass");
        decoder.finish().expect("consume dense incompatible pass");
        assert_eq!(decoded.len(), INCOMPATIBLE_REPLAYS);
        assert!(decoded.iter().all(|replay| matches!(
            replay,
            ReplayIndexes::DeterministicallyIncompatible {
                configuration: 0,
                reason: FindingReplayIncompatibility::PrefixDiverged,
            }
        )));
    }

    #[test]
    fn dense_incompatible_v4_pass_rejects_truncation() {
        let mut bytes = dense_incompatible_bytes();
        bytes.pop();
        let mut decoder = Decoder::new(&bytes);
        let mut validation_references = 0;

        assert!(matches!(
            decode_replay_indexes(
                &mut decoder,
                &mut validation_references,
                PreparedSemanticResultVersion::V4,
            ),
            Err(PreparedSemanticResultCodecError::Truncated)
        ));
    }
}
