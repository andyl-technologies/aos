//! Record contracts.

use super::*;

/// Canonical modeled result of one admitted attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    schema_version: u32,
    attempt: AttemptId,
    child: ConfigurationId,
    child_content: ConfigurationArtifactId,
    path: BranchPathId,
    stop: StopOutcome,
    measurements: MeasurementSetId,
    properties: PropertyVerdictSetId,
    coverage: CoverageProjectionId,
    discovered_choices: BTreeSet<ChoiceOpportunityId>,
    produced_selections: BTreeSet<SelectionId>,
}

/// Modeled child state and evidence produced by one completed attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationOutcome {
    child: ConfigurationId,
    child_content: ConfigurationArtifactId,
    path: BranchPathId,
    stop: StopOutcome,
    measurements: MeasurementSetId,
    properties: PropertyVerdictSetId,
    coverage: CoverageProjectionId,
}

impl ObservationOutcome {
    /// Builds the child and evidence portion of an observation.
    #[must_use]
    pub const fn new(
        child: ConfigurationId,
        child_content: ConfigurationArtifactId,
        path: BranchPathId,
        stop: StopOutcome,
        measurements: MeasurementSetId,
        properties: PropertyVerdictSetId,
        coverage: CoverageProjectionId,
    ) -> Self {
        Self {
            child,
            child_content,
            path,
            stop,
            measurements,
            properties,
            coverage,
        }
    }
}

impl Observation {
    /// Builds one bounded canonical attempt observation.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid stop outcome, too many discovered
    /// choices, or an oversized encoded record.
    /// Builds the outcome portion accepted by [`Self::new`].
    #[must_use]
    pub const fn outcome(
        child: ConfigurationId,
        child_content: ConfigurationArtifactId,
        path: BranchPathId,
        stop: StopOutcome,
        measurements: MeasurementSetId,
        properties: PropertyVerdictSetId,
        coverage: CoverageProjectionId,
    ) -> ObservationOutcome {
        ObservationOutcome::new(
            child,
            child_content,
            path,
            stop,
            measurements,
            properties,
            coverage,
        )
    }

    /// Builds one bounded canonical attempt observation.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid stop outcome, too many discovered
    /// choices, or an oversized encoded record.
    pub fn new(
        attempt: AttemptId,
        outcome: ObservationOutcome,
        discovered_choices: BTreeSet<ChoiceOpportunityId>,
    ) -> Result<Self, CampaignCodecError> {
        let schema_version = observation_schema_version(&outcome.stop, false);
        Self::from_versioned(Self {
            schema_version,
            attempt,
            child: outcome.child,
            child_content: outcome.child_content,
            path: outcome.path,
            stop: outcome.stop,
            measurements: outcome.measurements,
            properties: outcome.properties,
            coverage: outcome.coverage,
            discovered_choices,
            produced_selections: BTreeSet::new(),
        })
    }

    /// Attaches the nonempty selection closure produced by this attempt.
    ///
    /// # Errors
    ///
    /// Returns an error after a nonempty selection closure was already
    /// attached, or when the combined choice-reference count or encoded
    /// observation exceeds its fixed bound.
    pub(crate) fn with_produced_selections(
        mut self,
        produced_selections: BTreeSet<SelectionId>,
    ) -> Result<Self, CampaignCodecError> {
        if !self.produced_selections.is_empty() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "observation already carries produced selections",
            });
        }
        if produced_selections.is_empty() {
            return Ok(self);
        }
        self.schema_version = observation_schema_version(&self.stop, true);
        self.produced_selections = produced_selections;
        Self::from_versioned(self)
    }

    fn from_versioned(value: Self) -> Result<Self, CampaignCodecError> {
        value.stop.validate()?;
        if matches!(&value.stop, StopOutcome::ObservationReached(proof) if proof.child() != value.child)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "observation stop proof disagrees with child configuration",
            });
        }
        if value.discovered_choices.len() > MAX_DISCOVERED_CHOICES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "observation-discovered-choice-count",
            });
        }
        if value
            .discovered_choices
            .len()
            .checked_add(value.produced_selections.len())
            .is_none_or(|count| count > MAX_DISCOVERED_CHOICES)
        {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "observation-choice-reference-count",
            });
        }
        let has_produced_selections = !value.produced_selections.is_empty();
        if value.schema_version != observation_schema_version(&value.stop, has_produced_selections)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported observation schema or stop outcome",
            });
        }
        codec::ensure_encoded_size(&value, MAX_RECORD_BYTES, "observation-encoded-bytes")?;
        Ok(value)
    }

    /// Returns the admitted attempt.
    #[must_use]
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// Returns the child configuration semantic identity.
    #[must_use]
    pub const fn child(&self) -> ConfigurationId {
        self.child
    }

    /// Returns the exact retained child configuration artifact.
    #[must_use]
    pub const fn child_content(&self) -> ConfigurationArtifactId {
        self.child_content
    }

    /// Returns the exact admitted branch path.
    #[must_use]
    pub const fn path(&self) -> BranchPathId {
        self.path
    }

    /// Returns the modeled stop outcome.
    #[must_use]
    pub const fn stop(&self) -> &StopOutcome {
        &self.stop
    }

    /// Returns the exact measurement set.
    #[must_use]
    pub const fn measurements(&self) -> MeasurementSetId {
        self.measurements
    }

    /// Returns the exact property-verdict set.
    #[must_use]
    pub const fn properties(&self) -> PropertyVerdictSetId {
        self.properties
    }

    /// Returns the exact coverage projection.
    #[must_use]
    pub const fn coverage(&self) -> CoverageProjectionId {
        self.coverage
    }

    /// Returns discovered choice opportunities in canonical identity order.
    #[must_use]
    pub const fn discovered_choices(&self) -> &BTreeSet<ChoiceOpportunityId> {
        &self.discovered_choices
    }

    /// Returns selections produced while continuing through discovered choices.
    #[must_use]
    pub const fn produced_selections(&self) -> &BTreeSet<SelectionId> {
        &self.produced_selections
    }

    /// Returns strict canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, invalid, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_record(bytes, "observation-encoded-bytes")
    }

    /// Returns the exact observation identity.
    ///
    /// # Errors
    ///
    /// Returns an error if envelope construction fails.
    pub fn id(&self) -> Result<ObservationId, CampaignCodecError> {
        ObservationId::from_content_id(
            crate::ObjectEnvelope::for_record_versioned(
                crate::CampaignRecordKind::Observation,
                self.schema_version,
                crate::object::content_children(self.content_children())?,
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        let mut children = vec![
            ("attempt".to_owned(), self.attempt.content_id()),
            ("child".to_owned(), self.child_content.content_id()),
            ("path".to_owned(), self.path.content_id()),
            ("measurements".to_owned(), self.measurements.content_id()),
            ("properties".to_owned(), self.properties.content_id()),
            ("coverage".to_owned(), self.coverage.content_id()),
        ];
        children.extend(
            self.discovered_choices
                .iter()
                .enumerate()
                .map(|(index, choice)| {
                    (
                        format!("discovered-choice.{index:04x}"),
                        choice.content_id(),
                    )
                }),
        );
        children.extend(
            self.produced_selections
                .iter()
                .enumerate()
                .map(|(index, selection)| {
                    (
                        format!("produced-selection.{index:04x}"),
                        selection.content_id(),
                    )
                }),
        );
        children
    }

    pub(crate) const fn schema_version(&self) -> u32 {
        self.schema_version
    }
}

impl Canonical for Observation {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.attempt.encode(encoder);
        self.child.encode(encoder);
        self.child_content.encode(encoder);
        self.path.encode(encoder);
        self.stop.encode(encoder);
        self.measurements.encode(encoder);
        self.properties.encode(encoder);
        self.coverage.encode(encoder);
        self.discovered_choices.encode(encoder);
        if observation_schema_has_produced_selections(self.schema_version) {
            self.produced_selections.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        if !matches!(
            schema_version,
            RECORD_SCHEMA_VERSION..=OBSERVATION_SCHEMA_VERSION
        ) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported observation schema or stop outcome",
            });
        }
        let attempt = AttemptId::decode(decoder)?;
        let child = ConfigurationId::decode(decoder)?;
        let child_content = ConfigurationArtifactId::decode(decoder)?;
        let path = BranchPathId::decode(decoder)?;
        let stop = StopOutcome::decode(decoder)?;
        let measurements = MeasurementSetId::decode(decoder)?;
        let properties = PropertyVerdictSetId::decode(decoder)?;
        let coverage = CoverageProjectionId::decode(decoder)?;
        let discovered_choices = decoder.set_bounded(
            MAX_DISCOVERED_CHOICES,
            "observation-discovered-choice-count",
        )?;
        let produced_selections = if observation_schema_has_produced_selections(schema_version) {
            decoder.set_bounded(
                MAX_DISCOVERED_CHOICES,
                "observation-produced-selection-count",
            )?
        } else {
            BTreeSet::new()
        };
        Self::from_versioned(Self {
            schema_version,
            attempt,
            child,
            child_content,
            path,
            stop,
            measurements,
            properties,
            coverage,
            discovered_choices,
            produced_selections,
        })
    }
}

fn observation_schema_version(stop: &StopOutcome, has_produced_selections: bool) -> u32 {
    let mut version = match (
        matches!(stop, StopOutcome::ScenarioFailure(_)),
        has_produced_selections,
    ) {
        (false, false) => RECORD_SCHEMA_VERSION,
        (true, false) => SCENARIO_FAILURE_OBSERVATION_SCHEMA_VERSION,
        (false, true) => PRODUCED_SELECTION_OBSERVATION_SCHEMA_VERSION,
        (true, true) => SCENARIO_FAILURE_PRODUCED_SELECTION_OBSERVATION_SCHEMA_VERSION,
    };
    if stop.uses_extended_stop_schema() {
        version += EXTENDED_STOP_OBSERVATION_SCHEMA_OFFSET;
    } else if stop.uses_observation_stop_schema() {
        version += OBSERVATION_STOP_SCHEMA_OFFSET;
    }
    version
}

const fn observation_schema_has_produced_selections(schema_version: u32) -> bool {
    matches!(
        schema_version,
        PRODUCED_SELECTION_OBSERVATION_SCHEMA_VERSION
            | SCENARIO_FAILURE_PRODUCED_SELECTION_OBSERVATION_SCHEMA_VERSION
            | 7
            | 8
            | 11
            | 12
    )
}

pub(super) fn require_schema(actual: u32) -> Result<(), CampaignCodecError> {
    if actual == RECORD_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported observation record schema version",
        })
    }
}

pub(super) fn decode_record<T: Canonical>(
    bytes: &[u8],
    limit: &'static str,
) -> Result<T, CampaignCodecError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(CampaignCodecError::LimitExceeded { limit });
    }
    codec::decode(bytes)
}
