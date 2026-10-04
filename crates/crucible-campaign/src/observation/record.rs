//! Record contracts.

use super::*;

/// Canonical modeled result of one admitted attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
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
    resolved_effect_trace: Option<ContentId>,
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
        Self::validate(Self {
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
            resolved_effect_trace: None,
        })
    }

    /// Binds the exact canonical resolved-effect trace retained for this attempt.
    ///
    /// # Errors
    ///
    /// Returns an error if the trace identity is invalid or already attached.
    pub fn with_resolved_effect_trace(
        mut self,
        trace: ContentId,
    ) -> Result<Self, CampaignCodecError> {
        if trace.kind() != crucible_cas::content_store::ObjectKind::Trace
            || trace.schema_version() != 1
            || self.resolved_effect_trace.is_some()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "observation resolved-effect trace identity is invalid",
            });
        }
        self.resolved_effect_trace = Some(trace);
        Self::validate(self)
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
        self.produced_selections = produced_selections;
        Self::validate(self)
    }

    fn validate(value: Self) -> Result<Self, CampaignCodecError> {
        value.stop.validate()?;
        if value.resolved_effect_trace.is_some_and(|trace| {
            trace.kind() != crucible_cas::content_store::ObjectKind::Trace
                || trace.schema_version() != 1
        }) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "observation resolved-effect trace identity is invalid",
            });
        }
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

    /// Returns the exact retained canonical resolved-effect trace, when present.
    #[must_use]
    pub const fn resolved_effect_trace(&self) -> Option<ContentId> {
        self.resolved_effect_trace
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
                OBSERVATION_SCHEMA_VERSION,
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
        if let Some(trace) = self.resolved_effect_trace {
            children.push(("resolved-effect-trace".to_owned(), trace));
        }
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
        OBSERVATION_SCHEMA_VERSION
    }
}

impl Canonical for Observation {
    fn encode(&self, encoder: &mut Encoder) {
        OBSERVATION_SCHEMA_VERSION.encode(encoder);
        self.attempt.encode(encoder);
        self.child.encode(encoder);
        self.child_content.encode(encoder);
        self.path.encode(encoder);
        self.stop.encode(encoder);
        self.measurements.encode(encoder);
        self.properties.encode(encoder);
        self.coverage.encode(encoder);
        self.discovered_choices.encode(encoder);
        self.produced_selections.encode(encoder);
        self.resolved_effect_trace.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != OBSERVATION_SCHEMA_VERSION {
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
        let produced_selections = decoder.set_bounded(
            MAX_DISCOVERED_CHOICES,
            "observation-produced-selection-count",
        )?;
        let resolved_effect_trace = Option::<ContentId>::decode(decoder)?;
        Self::validate(Self {
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
            resolved_effect_trace,
        })
    }
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
