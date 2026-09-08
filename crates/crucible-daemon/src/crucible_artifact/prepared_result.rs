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
//! bindings. This codec does not possess authenticated scenario measurement
//! definitions and therefore does not replay the leaf or compare the retained
//! evaluation payload. Production preparation and recovery must call
//! [`crate::verify_crucible_measurement_publication`] for the observation and
//! every finding replay before any child-first publication.

use std::collections::{BTreeMap, BTreeSet};

use crucible::ScenarioDefForm;
use crucible_campaign::{
    CampaignCodecError, ChoiceDiscovery, ChoiceDomain, ChoiceOpportunity, ConfigurationArtifact,
    CoverageProjection, FindingCandidateBundle, FindingKind, FindingTarget, MeasurementSet,
    Observation, ObservationCandidate, PropertyVerdict, PropertyVerdictSet, ReproductionArtifact,
    ScenarioArtifact, SelectableDeclaration, Selection,
};
use thiserror::Error;

use super::finding_replay::PreparedFindingReplayRecords;
use super::{
    CrucibleArtifactError, MAX_CRUCIBLE_FINDING_REPLAY_BYTES, MAX_CRUCIBLE_FINDING_REPLAY_RECORDS,
    PreparedCrucibleFindingCandidate, RecordedFindingReplay, prepare_minimized_reproduction,
    prepare_original_reproduction, replay_recorded_signature_pass,
};
use crate::{
    CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V2, CrucibleMeasurementError,
    CrucibleMeasurementReplayEvidence, verify_crucible_measurement_publication,
};

const PREPARED_RESULT_MAGIC_V1: &[u8] = b"crucible.executor.prepared-semantic-attempt-result.v1\0";
const PREPARED_RESULT_MAGIC_V2: &[u8] = b"crucible.executor.prepared-semantic-attempt-result.v2\0";
const MAX_PREPARED_RESULT_RECORDS: usize = 200_000;
const MAX_RECORD_BYTES: usize = 64 * 1024 * 1024;
const MAX_REPLAY_VALIDATION_REFERENCES: usize = 4 * 1024 * 1024;

/// Maximum encoded bytes retained by one prepared semantic result journal.
pub const MAX_PREPARED_SEMANTIC_RESULT_BYTES: usize = 1024 * 1024 * 1024;

/// Complete immutable semantic result retained across publication retries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedSemanticAttemptResult {
    observation: ObservationCandidate,
    measurement_replay_evidence: Vec<CrucibleMeasurementReplayEvidence>,
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
    /// This authenticates closure ownership only; callers must separately run
    /// [`crate::verify_crucible_measurement_publication`] with the authenticated
    /// scenario definitions before publication.
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
            finding,
        })
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

    /// Returns the prepared finding closure, when execution found one.
    #[must_use]
    pub const fn finding(&self) -> Option<&PreparedCrucibleFindingCandidate> {
        self.finding.as_ref()
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

                let measurement = measurements
                    .get(&replay.measurements)
                    .ok_or_else(|| inconsistent("finding replay measurement record"))?;
                let configuration = configurations
                    .get(&replay.configuration)
                    .copied()
                    .ok_or_else(|| inconsistent("finding replay measurement configuration"))?;
                if verified_pairs.insert((replay.measurements, configuration)) {
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

        let mut encoder = Encoder::new(maximum_bytes.min(MAX_PREPARED_SEMANTIC_RESULT_BYTES));
        encoder.raw(PREPARED_RESULT_MAGIC_V2)?;
        encode_observation(&mut encoder, &self.observation)?;
        encode_measurement_evidence(&mut encoder, &self.measurement_replay_evidence)?;
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
            PreparedSemanticResultVersion::V2 => decode_measurement_evidence(&mut decoder)?,
        };
        let finding = match decoder.byte()? {
            0 => None,
            1 => Some(decode_finding(&mut decoder)?),
            _ => return Err(PreparedSemanticResultCodecError::InvalidTag),
        };
        decoder.finish()?;

        let value = Self::new_with_measurement_replay_evidence(
            observation,
            measurement_replay_evidence,
            finding,
        )?;
        let canonical = match version {
            PreparedSemanticResultVersion::V1 => {
                value.canonical_v1_bytes_with_limit(maximum_bytes)?
            }
            PreparedSemanticResultVersion::V2 => value.canonical_bytes_with_limit(maximum_bytes)?,
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
        Option<PreparedCrucibleFindingCandidate>,
    ) {
        (
            self.observation,
            self.measurement_replay_evidence,
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
        validate_pair(&self.observation, self.finding.as_ref())?;

        let mut encoder = Encoder::new(maximum_bytes.min(MAX_PREPARED_SEMANTIC_RESULT_BYTES));
        encoder.raw(PREPARED_RESULT_MAGIC_V1)?;
        encode_observation(&mut encoder, &self.observation)?;
        match &self.finding {
            Some(finding) => {
                encoder.byte(1)?;
                encode_finding(&mut encoder, finding)?;
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
}

impl PreparedSemanticResultVersion {
    /// Detects the declared version of a complete prepared-result payload.
    pub(crate) fn from_payload(bytes: &[u8]) -> Option<Self> {
        if bytes.starts_with(PREPARED_RESULT_MAGIC_V1) {
            Some(Self::V1)
        } else if bytes.starts_with(PREPARED_RESULT_MAGIC_V2) {
            Some(Self::V2)
        } else {
            None
        }
    }

    const fn magic(self) -> &'static [u8] {
        match self {
            Self::V1 => PREPARED_RESULT_MAGIC_V1,
            Self::V2 => PREPARED_RESULT_MAGIC_V2,
        }
    }
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

    if let Some(finding) = finding {
        let referenced_measurements = finding
            .minimization_replays
            .iter()
            .chain(&finding.verification_replays)
            .map(|replay| replay.measurements)
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
            let measurement = measurements
                .get(&replay.measurements)
                .ok_or_else(|| inconsistent("finding replay measurement record"))?;
            if !measurement_requires_replay_evidence(measurement) {
                continue;
            }
            let configuration = configurations
                .get(&replay.configuration)
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
            encode_finding(&mut encoder, finding)?;
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

    ObservationCandidate::new(
        child,
        measurements,
        properties,
        coverage,
        discoveries,
        observation,
    )?
    .with_produced_selections(selections)
    .map_err(Into::into)
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
    encode_replays(encoder, value)?;
    encoder.record(&value.bundle.canonical_bytes())?;
    Ok(())
}

fn decode_finding(
    decoder: &mut Decoder<'_>,
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
    let minimization_indexes = decode_replay_indexes(decoder, &mut replay_validation_references)?;
    let verification_indexes = decode_replay_indexes(decoder, &mut replay_validation_references)?;
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
    let artifact = crucible::ReproductionArtifact::from_compact_binary(value.original.payload())
        .map_err(|source| CrucibleArtifactError::InvalidPayload {
            artifact: "journal original finding reproduction",
            source: Box::new(source),
        })?;
    let replay = artifact
        .replay()
        .map_err(|source| CrucibleArtifactError::InvalidPayload {
            artifact: "journal original finding replay",
            source: Box::new(source),
        })?;
    let original_finding = crucible::FindingReproductionArtifact {
        discovery_path: value.discovery_path,
        finding_fingerprint: crucible::ContentHash {
            bytes: value.original.finding_fingerprint().as_bytes(),
        },
        configuration: crucible::Configuration {
            def: artifact.scenario_def(),
            schedule: artifact.schedule().clone(),
        }
        .id(),
        artifact,
        replay,
    };
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
    let (expected_minimized_configuration, expected_minimized) =
        prepare_minimized_reproduction(original, &minimization)?;
    if expected_minimized_configuration != value.minimized_configuration
        || expected_minimized != value.minimized
    {
        return Err(PreparedSemanticResultCodecError::Inconsistent {
            component: "minimized finding reconstruction",
        });
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
            &replay.configuration,
            &mut referenced_bytes,
            &mut reference_count,
            "finding replay configuration",
        )?;
        charge_reference(
            &measurements,
            &replay.measurements,
            &mut referenced_bytes,
            &mut reference_count,
            "finding replay measurements",
        )?;
        charge_reference(
            &properties,
            &replay.properties,
            &mut referenced_bytes,
            &mut reference_count,
            "finding replay properties",
        )?;
        charge_reference(
            &coverage,
            &replay.coverage,
            &mut referenced_bytes,
            &mut reference_count,
            "finding replay coverage",
        )?;
        for opportunity_id in &replay.opportunities {
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
        for selection_id in &replay.selections {
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
        let (configuration, _) = configurations.get(&replay.configuration).ok_or(
            PreparedSemanticResultCodecError::Inconsistent {
                component: "finding replay configuration",
            },
        )?;
        let (measurement, _) = measurements.get(&replay.measurements).ok_or(
            PreparedSemanticResultCodecError::Inconsistent {
                component: "finding replay measurements",
            },
        )?;
        let (property, _) = properties.get(&replay.properties).ok_or(
            PreparedSemanticResultCodecError::Inconsistent {
                component: "finding replay properties",
            },
        )?;
        let (projection, _) = coverage.get(&replay.coverage).ok_or(
            PreparedSemanticResultCodecError::Inconsistent {
                component: "finding replay coverage",
            },
        )?;
        let mut discoveries = Vec::with_capacity(replay.opportunities.len());
        for opportunity_id in &replay.opportunities {
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
        let replay_selections = replay
            .selections
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
            replay.signature.clone(),
            (*configuration).clone(),
            (*measurement).clone(),
            (*property).clone(),
            (*projection).clone(),
            discoveries,
            replay_selections,
        )?;
        if reconstructed.configuration().id()? != replay.configuration
            || reconstructed.signature() != replay.signature.as_ref()
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
    encode_replay_pass(encoder, &value.minimization_replays, &indexes)?;
    encode_replay_pass(encoder, &value.verification_replays, &indexes)
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
) -> Result<(), PreparedSemanticResultCodecError> {
    encoder.count(replays.len())?;
    for replay in replays {
        encoder.index(find_index(
            &indexes.configurations,
            replay.configuration.content_id(),
        )?)?;
        encoder.index(find_index(
            &indexes.measurements,
            replay.measurements.content_id(),
        )?)?;
        encoder.index(find_index(
            &indexes.properties,
            replay.properties.content_id(),
        )?)?;
        encoder.index(find_index(&indexes.coverage, replay.coverage.content_id())?)?;
        encoder.count(replay.opportunities.len())?;
        for opportunity in &replay.opportunities {
            encoder.index(find_index(
                &indexes.opportunities,
                opportunity.content_id(),
            )?)?;
        }
        encoder.count(replay.selections.len())?;
        for selection in &replay.selections {
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
struct ReplayIndexes {
    configuration: usize,
    measurements: usize,
    properties: usize,
    coverage: usize,
    opportunities: Vec<usize>,
    selections: Vec<usize>,
}

fn decode_replay_indexes(
    decoder: &mut Decoder<'_>,
    validation_references: &mut usize,
) -> Result<Vec<ReplayIndexes>, PreparedSemanticResultCodecError> {
    let count = decoder.count_bounded(MAX_CRUCIBLE_FINDING_REPLAY_RECORDS)?;
    charge_validation_references(validation_references, count, 4)?;
    decoder.preflight_collection(count, 6 * size_of::<u32>())?;
    let mut replays = Vec::with_capacity(count);
    for _ in 0..count {
        let configuration = decoder.index()?;
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
        replays.push(ReplayIndexes {
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
        .map(|(indexes, signature)| {
            Ok(RecordedFindingReplay {
                signature: signature.clone(),
                configuration: *indexed(configurations, indexes.configuration)?,
                measurements: *indexed(measurements, indexes.measurements)?,
                properties: *indexed(properties, indexes.properties)?,
                coverage: *indexed(coverage, indexes.coverage)?,
                opportunities: indexes
                    .opportunities
                    .iter()
                    .map(|index| indexed(opportunities, *index).copied())
                    .collect::<Result<Vec<_>, PreparedSemanticResultCodecError>>()?,
                selections: indexes
                    .selections
                    .iter()
                    .map(|index| indexed(selections, *index).copied())
                    .collect::<Result<Vec<_>, PreparedSemanticResultCodecError>>()?,
            })
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
