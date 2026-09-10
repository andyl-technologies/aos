//! Branch paths, attempts, and attempt-admission records.

use super::*;

/// Modeled scheduler control applied when continuing an authenticated boundary.
///
/// The campaign layer owns the closed control shape and its resource bounds.
/// An executor that recognizes the override form must additionally decode each
/// decision with its scheduler schema and reject unsupported decision kinds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttemptContinuationInput {
    /// Re-seeds post-boundary deterministic decision streams.
    SchedulerReseed {
        /// Canonical observation proving the selected source boundary.
        source_observation: ObservationId,
        /// Exact scheduler frontier where the new seed begins.
        source_frontier_ticks: u64,
        /// Complete deterministic stream seed.
        seed: [u8; 32],
    },
    /// Applies an ordered, finite set of recorded scheduler overrides.
    SchedulerOverrides {
        /// Canonical observation proving the selected source boundary.
        source_observation: ObservationId,
        /// Exact scheduler frontier where override matching begins.
        source_frontier_ticks: u64,
        /// Canonical scheduler decision records in requested order.
        decisions: Vec<Vec<u8>>,
    },
}

impl AttemptContinuationInput {
    /// Builds a bounded scheduler re-seed input.
    #[must_use]
    pub const fn scheduler_reseed(
        source_observation: ObservationId,
        source_frontier_ticks: u64,
        seed: [u8; 32],
    ) -> Self {
        Self::SchedulerReseed {
            source_observation,
            source_frontier_ticks,
            seed,
        }
    }

    /// Builds a bounded ordered scheduler-override input.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the set is empty, contains duplicate
    /// records, or exceeds the fixed count, item, or aggregate byte bounds.
    pub fn scheduler_overrides(
        source_observation: ObservationId,
        source_frontier_ticks: u64,
        decisions: Vec<Vec<u8>>,
    ) -> Result<Self, CampaignCodecError> {
        validate_continuation_override_decisions(&decisions)?;
        Ok(Self::SchedulerOverrides {
            source_observation,
            source_frontier_ticks,
            decisions,
        })
    }

    /// Validates encoded scheduler overrides before a source observation is known.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the set is empty, contains duplicate
    /// records, or exceeds the fixed count, item, or aggregate byte bounds.
    pub fn validate_scheduler_overrides(decisions: &[Vec<u8>]) -> Result<(), CampaignCodecError> {
        validate_continuation_override_decisions(decisions)
    }

    /// Returns the canonical observation proving the source boundary.
    #[must_use]
    pub const fn source_observation(&self) -> ObservationId {
        match self {
            Self::SchedulerReseed {
                source_observation, ..
            }
            | Self::SchedulerOverrides {
                source_observation, ..
            } => *source_observation,
        }
    }

    /// Returns the exact scheduler frontier where this input begins.
    #[must_use]
    pub const fn source_frontier_ticks(&self) -> u64 {
        match self {
            Self::SchedulerReseed {
                source_frontier_ticks,
                ..
            }
            | Self::SchedulerOverrides {
                source_frontier_ticks,
                ..
            } => *source_frontier_ticks,
        }
    }

    fn validate(&self) -> Result<(), CampaignCodecError> {
        match self {
            Self::SchedulerReseed { .. } => Ok(()),
            Self::SchedulerOverrides { decisions, .. } => {
                validate_continuation_override_decisions(decisions)
            }
        }
    }
}

impl Canonical for AttemptContinuationInput {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::SchedulerReseed {
                source_observation,
                source_frontier_ticks,
                seed,
            } => {
                encoder.u8(0);
                source_observation.encode(encoder);
                encoder.u64(*source_frontier_ticks);
                encoder.fixed(seed);
            }
            Self::SchedulerOverrides {
                source_observation,
                source_frontier_ticks,
                decisions,
            } => {
                encoder.u8(1);
                source_observation.encode(encoder);
                encoder.u64(*source_frontier_ticks);
                decisions.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::scheduler_reseed(
                ObservationId::decode(decoder)?,
                decoder.u64()?,
                decoder.fixed::<32>()?,
            )),
            1 => {
                let source_observation = ObservationId::decode(decoder)?;
                let source_frontier_ticks = decoder.u64()?;
                let mut aggregate_bytes = 0;
                let decisions = decoder.sequence_bounded(
                    MAX_CONTINUATION_OVERRIDE_DECISIONS,
                    "attempt-continuation-override-count",
                    |decoder| {
                        decoder.byte_sequence_bounded_charged(
                            MAX_CONTINUATION_OVERRIDE_DECISION_BYTES,
                            "attempt-continuation-override-item-bytes",
                            &mut aggregate_bytes,
                            MAX_CONTINUATION_OVERRIDE_BYTES,
                            "attempt-continuation-override-aggregate-bytes",
                        )
                    },
                )?;
                Self::scheduler_overrides(source_observation, source_frontier_ticks, decisions)
            }
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "attempt-continuation-input",
                tag,
            }),
        }
    }
}

fn validate_continuation_override_decisions(
    decisions: &[Vec<u8>],
) -> Result<(), CampaignCodecError> {
    if decisions.is_empty() {
        return Err(CampaignCodecError::InvalidValue {
            reason: "attempt continuation override set is empty",
        });
    }
    if decisions.len() > MAX_CONTINUATION_OVERRIDE_DECISIONS {
        return Err(CampaignCodecError::LimitExceeded {
            limit: "attempt-continuation-override-count",
        });
    }

    let mut aggregate_bytes = 0usize;
    let mut unique = BTreeSet::new();
    for decision in decisions {
        if decision.len() > MAX_CONTINUATION_OVERRIDE_DECISION_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "attempt-continuation-override-item-bytes",
            });
        }
        aggregate_bytes = aggregate_bytes.checked_add(decision.len()).ok_or(
            CampaignCodecError::LimitExceeded {
                limit: "attempt-continuation-override-aggregate-bytes",
            },
        )?;
        if aggregate_bytes > MAX_CONTINUATION_OVERRIDE_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "attempt-continuation-override-aggregate-bytes",
            });
        }
        if !unique.insert(decision) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "attempt continuation override set contains a duplicate decision",
            });
        }
    }
    Ok(())
}

/// One branch-point-scoped edge in an authenticated execution path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BranchPathSegment {
    branch_point: BranchPointId,
    edge: BranchEdgeId,
}

impl BranchPathSegment {
    /// Builds one exact branch-point and edge pair.
    #[must_use]
    pub const fn new(branch_point: BranchPointId, edge: BranchEdgeId) -> Self {
        Self { branch_point, edge }
    }

    /// Returns the semantic branch point receiving descendant credit.
    #[must_use]
    pub const fn branch_point(self) -> BranchPointId {
        self.branch_point
    }

    /// Returns the selected semantic edge at the branch point.
    #[must_use]
    pub const fn edge(self) -> BranchEdgeId {
        self.edge
    }
}

impl Canonical for BranchPathSegment {
    fn encode(&self, encoder: &mut Encoder) {
        self.branch_point.encode(encoder);
        self.edge.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self::new(
            BranchPointId::decode(decoder)?,
            BranchEdgeId::decode(decoder)?,
        ))
    }
}

/// Authenticated ordered semantic edge path used for guidance backpropagation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchPath {
    schema_version: u32,
    edges: Vec<BranchEdgeId>,
    segments: Vec<BranchPathSegment>,
}

impl BranchPath {
    /// Builds a bounded branch-point-scoped path.
    ///
    /// An empty path represents genesis discovery. New paths retain each
    /// branch point beside its non-invertible edge identity so observation
    /// credit can be rebuilt without process-local graph state.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the path exceeds 65,536 edges.
    pub fn new(segments: Vec<BranchPathSegment>) -> Result<Self, CampaignCodecError> {
        if segments.len() > MAX_BRANCH_PATH_EDGES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "branch-path-edge-count",
            });
        }
        let edges = segments.iter().map(|segment| segment.edge()).collect();
        Ok(Self {
            schema_version: BRANCH_PATH_SCHEMA_VERSION,
            edges,
            segments,
        })
    }

    /// Returns edges from root to leaf.
    #[must_use]
    pub fn edges(&self) -> &[BranchEdgeId] {
        &self.edges
    }

    /// Returns scoped path segments, or `None` for a decoded legacy v1 path.
    ///
    /// Version 1 remains readable with its exact historical content identity,
    /// but its edge hashes cannot be inverted into branch points. New writers
    /// always produce version 2 scoped segments.
    #[must_use]
    pub fn segments(&self) -> Option<&[BranchPathSegment]> {
        (self.schema_version == BRANCH_PATH_SCHEMA_VERSION).then_some(self.segments.as_slice())
    }

    /// Returns strict canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes a strict canonical branch path.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, invalid, or
    /// oversized bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_exact_record(bytes, "branch-path-encoded-bytes")
    }

    /// Returns the exact stored path identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<BranchPathId, CampaignCodecError> {
        BranchPathId::from_content_id(crate::ObjectEnvelope::for_branch_path(self)?.content_id())
    }

    pub(crate) const fn schema_version(&self) -> u32 {
        self.schema_version
    }
}

impl Canonical for BranchPath {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        if self.schema_version == RECORD_SCHEMA_VERSION {
            self.edges.encode(encoder);
        } else {
            self.segments.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match u32::decode(decoder)? {
            RECORD_SCHEMA_VERSION => Ok(Self {
                schema_version: RECORD_SCHEMA_VERSION,
                edges: decoder.sequence_bounded(
                    MAX_BRANCH_PATH_EDGES,
                    "branch-path-edge-count",
                    BranchEdgeId::decode,
                )?,
                segments: Vec::new(),
            }),
            BRANCH_PATH_SCHEMA_VERSION => Self::new(decoder.sequence_bounded(
                MAX_BRANCH_PATH_EDGES,
                "branch-path-edge-count",
                BranchPathSegment::decode,
            )?),
            _ => Err(CampaignCodecError::InvalidValue {
                reason: "unsupported exploration record schema version",
            }),
        }
    }
}

/// Semantic starting boundary for one immutable execution attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttemptStart {
    /// Realizes an existing configuration until the next boundary.
    Discover {
        /// Exact starting configuration artifact.
        configuration: ConfigurationArtifactId,
    },
    /// Applies exactly one recorded selection at a known parent.
    Branch {
        /// Semantic edge being realized.
        edge: BranchEdgeId,
        /// Exact parent configuration artifact.
        parent: ConfigurationArtifactId,
        /// Exact recorded selection.
        selection: SelectionId,
    },
    /// Continues from the exact modeled boundary reached by an older attempt.
    AfterAttempt {
        /// Immutable attempt whose declared stop produced the boundary.
        origin: AttemptId,
        /// Exact configuration artifact reached at the origin attempt's stop.
        reached: ConfigurationArtifactId,
    },
}

impl Canonical for AttemptStart {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Discover { configuration } => {
                encoder.u8(0);
                configuration.encode(encoder);
            }
            Self::Branch {
                edge,
                parent,
                selection,
            } => {
                encoder.u8(1);
                edge.encode(encoder);
                parent.encode(encoder);
                selection.encode(encoder);
            }
            Self::AfterAttempt { origin, reached } => {
                encoder.u8(2);
                origin.encode(encoder);
                reached.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Discover {
                configuration: ConfigurationArtifactId::decode(decoder)?,
            }),
            1 => Ok(Self::Branch {
                edge: BranchEdgeId::decode(decoder)?,
                parent: ConfigurationArtifactId::decode(decoder)?,
                selection: SelectionId::decode(decoder)?,
            }),
            2 => Ok(Self::AfterAttempt {
                origin: AttemptId::decode(decoder)?,
                reached: ConfigurationArtifactId::decode(decoder)?,
            }),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "attempt-start",
                tag,
            }),
        }
    }
}

/// Immutable semantic execution attempt independent of placement and retry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    schema_version: u32,
    start: AttemptStart,
    path: BranchPathId,
    stop: StopCondition,
    continuation_input: Option<AttemptContinuationInput>,
}

impl Attempt {
    /// Builds a semantic attempt.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an invalid stop condition.
    pub fn new(
        start: AttemptStart,
        path: BranchPathId,
        stop: StopCondition,
    ) -> Result<Self, CampaignCodecError> {
        stop.validate()?;
        let schema_version = match start {
            _ if stop.uses_observation_wire_schema() => OBSERVATION_STOP_ATTEMPT_SCHEMA_VERSION,
            AttemptStart::AfterAttempt { .. } => AFTER_ATTEMPT_SCHEMA_VERSION,
            AttemptStart::Discover { .. } | AttemptStart::Branch { .. }
                if stop.uses_extended_wire_schema() =>
            {
                ATTEMPT_SCHEMA_VERSION
            }
            AttemptStart::Discover { .. } | AttemptStart::Branch { .. } => RECORD_SCHEMA_VERSION,
        };
        Ok(Self {
            schema_version,
            start,
            path,
            stop,
            continuation_input: None,
        })
    }

    /// Builds a semantic continuation whose execution input is part of its identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] unless `start` is an `AfterAttempt`
    /// continuation, when the stop condition is invalid, or when a directly
    /// constructed override input is empty, duplicated, or exceeds its bounds.
    pub fn new_with_continuation_input(
        start: AttemptStart,
        path: BranchPathId,
        stop: StopCondition,
        continuation_input: AttemptContinuationInput,
    ) -> Result<Self, CampaignCodecError> {
        if !matches!(start, AttemptStart::AfterAttempt { .. }) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "attempt continuation input requires an after-attempt start",
            });
        }
        continuation_input.validate()?;
        stop.validate()?;
        let schema_version = if stop.uses_observation_wire_schema() {
            OBSERVATION_CONTINUATION_INPUT_ATTEMPT_SCHEMA_VERSION
        } else {
            CONTINUATION_INPUT_ATTEMPT_SCHEMA_VERSION
        };
        Ok(Self {
            schema_version,
            start,
            path,
            stop,
            continuation_input: Some(continuation_input),
        })
    }

    /// Returns the exact semantic start boundary.
    #[must_use]
    pub const fn start(&self) -> AttemptStart {
        self.start
    }

    /// Returns the authenticated root-to-leaf edge path.
    #[must_use]
    pub const fn path(&self) -> BranchPathId {
        self.path
    }

    /// Returns the semantic stop condition.
    #[must_use]
    pub const fn stop(&self) -> &StopCondition {
        &self.stop
    }

    /// Returns the modeled input applied at an authenticated continuation boundary.
    #[must_use]
    pub const fn continuation_input(&self) -> Option<&AttemptContinuationInput> {
        self.continuation_input.as_ref()
    }

    pub(crate) const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns strict canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes a strict canonical attempt.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, invalid, or
    /// oversized bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_exact_record(bytes, "attempt-encoded-bytes")
    }

    /// Returns the exact semantic attempt identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<AttemptId, CampaignCodecError> {
        AttemptId::from_content_id(
            crate::ObjectEnvelope::for_record_versioned(
                crate::CampaignRecordKind::Attempt,
                self.schema_version,
                crate::object::content_children(self.content_children())?,
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(&'static str, ContentId)> {
        let mut children = vec![("path", self.path.content_id())];
        match self.start {
            AttemptStart::Discover { configuration } => {
                children.push(("configuration", configuration.content_id()));
            }
            AttemptStart::Branch {
                parent, selection, ..
            } => {
                children.push(("parent", parent.content_id()));
                children.push(("selection", selection.content_id()));
            }
            AttemptStart::AfterAttempt { origin, reached } => {
                children.push(("origin-attempt", origin.content_id()));
                children.push(("reached-configuration", reached.content_id()));
            }
        }
        if let Some(input) = &self.continuation_input {
            children.push((
                "source-observation",
                input.source_observation().content_id(),
            ));
        }
        children
    }
}

impl Canonical for Attempt {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.start.encode(encoder);
        self.path.encode(encoder);
        self.stop.encode(encoder);
        if matches!(
            self.schema_version,
            CONTINUATION_INPUT_ATTEMPT_SCHEMA_VERSION
                | OBSERVATION_CONTINUATION_INPUT_ATTEMPT_SCHEMA_VERSION
        ) && let Some(continuation_input) = &self.continuation_input
        {
            continuation_input.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        if !matches!(
            schema_version,
            RECORD_SCHEMA_VERSION
                | ATTEMPT_SCHEMA_VERSION
                | AFTER_ATTEMPT_SCHEMA_VERSION
                | OBSERVATION_STOP_ATTEMPT_SCHEMA_VERSION
                | CONTINUATION_INPUT_ATTEMPT_SCHEMA_VERSION
                | OBSERVATION_CONTINUATION_INPUT_ATTEMPT_SCHEMA_VERSION
        ) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported attempt schema version",
            });
        }
        let start = AttemptStart::decode(decoder)?;
        let path = BranchPathId::decode(decoder)?;
        let stop = StopCondition::decode(decoder)?;
        let continuation_input = matches!(
            schema_version,
            CONTINUATION_INPUT_ATTEMPT_SCHEMA_VERSION
                | OBSERVATION_CONTINUATION_INPUT_ATTEMPT_SCHEMA_VERSION
        )
        .then(|| AttemptContinuationInput::decode(decoder))
        .transpose()?;
        let compatible = match schema_version {
            RECORD_SCHEMA_VERSION => {
                !stop.uses_extended_wire_schema()
                    && !stop.uses_observation_wire_schema()
                    && !matches!(start, AttemptStart::AfterAttempt { .. })
            }
            ATTEMPT_SCHEMA_VERSION => {
                stop.uses_extended_wire_schema()
                    && !matches!(start, AttemptStart::AfterAttempt { .. })
            }
            AFTER_ATTEMPT_SCHEMA_VERSION => {
                matches!(start, AttemptStart::AfterAttempt { .. })
                    && !stop.uses_observation_wire_schema()
                    && continuation_input.is_none()
            }
            OBSERVATION_STOP_ATTEMPT_SCHEMA_VERSION => {
                stop.uses_observation_wire_schema() && continuation_input.is_none()
            }
            CONTINUATION_INPUT_ATTEMPT_SCHEMA_VERSION => {
                matches!(start, AttemptStart::AfterAttempt { .. })
                    && !stop.uses_observation_wire_schema()
                    && continuation_input.is_some()
            }
            OBSERVATION_CONTINUATION_INPUT_ATTEMPT_SCHEMA_VERSION => {
                matches!(start, AttemptStart::AfterAttempt { .. })
                    && stop.uses_observation_wire_schema()
                    && continuation_input.is_some()
            }
            _ => false,
        };
        if !compatible {
            return Err(CampaignCodecError::InvalidValue {
                reason: "attempt schema disagrees with start or stop semantics",
            });
        }
        Ok(Self {
            schema_version,
            start,
            path,
            stop,
            continuation_input,
        })
    }
}

/// Unique execution basis or an additional deduplicated proposal cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttemptAdmissionRole {
    /// The one cause that spends attempt budget and fixes estimator provenance.
    ExecutionBasis {
        /// Proposal, absent for discovery and savepoint continuation.
        proposal: Option<ProposalId>,
        /// Operator/planner/debugger/policy cause.
        cause: BranchRequestCause,
        /// Global strict-mode order.
        admission_ordinal: AdmissionOrdinal,
    },
    /// Later proposal that converged on an already admitted attempt.
    AdditionalCause {
        /// Deduplicated proposal.
        proposal: ProposalId,
    },
}

impl Canonical for AttemptAdmissionRole {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::ExecutionBasis {
                proposal,
                cause,
                admission_ordinal,
            } => {
                encoder.u8(0);
                proposal.encode(encoder);
                cause.encode(encoder);
                admission_ordinal.encode(encoder);
            }
            Self::AdditionalCause { proposal } => {
                encoder.u8(1);
                proposal.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::ExecutionBasis {
                proposal: Option::decode(decoder)?,
                cause: BranchRequestCause::decode(decoder)?,
                admission_ordinal: AdmissionOrdinal::decode(decoder)?,
            }),
            1 => Ok(Self::AdditionalCause {
                proposal: ProposalId::decode(decoder)?,
            }),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "attempt-admission-role",
                tag,
            }),
        }
    }
}

/// Immutable provenance link from a cause to one semantic attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AttemptAdmission {
    schema_version: u32,
    attempt: AttemptId,
    role: AttemptAdmissionRole,
    retention_policy: Option<CampaignPolicyId>,
}

impl AttemptAdmission {
    /// Builds a legacy attempt admission record without an explicit policy binding.
    ///
    /// This constructor preserves the exact version 1 and version 2 encodings
    /// needed to validate historical campaign records. New admissions must use
    /// [`Self::new_policy_bound`].
    #[must_use]
    pub const fn new(attempt: AttemptId, role: AttemptAdmissionRole) -> Self {
        let schema_version = match role {
            AttemptAdmissionRole::ExecutionBasis {
                cause: BranchRequestCause::ScenarioDefault(_),
                ..
            } => ATTEMPT_ADMISSION_SCHEMA_VERSION,
            AttemptAdmissionRole::ExecutionBasis { .. }
            | AttemptAdmissionRole::AdditionalCause { .. } => RECORD_SCHEMA_VERSION,
        };
        Self {
            schema_version,
            attempt,
            role,
            retention_policy: None,
        }
    }

    /// Builds a version 3 attempt admission bound to its retention policy.
    #[must_use]
    pub const fn new_policy_bound(
        attempt: AttemptId,
        role: AttemptAdmissionRole,
        retention_policy: CampaignPolicyId,
    ) -> Self {
        Self {
            schema_version: ATTEMPT_ADMISSION_RETENTION_SCHEMA_VERSION,
            attempt,
            role,
            retention_policy: Some(retention_policy),
        }
    }

    /// Returns the admitted semantic attempt.
    #[must_use]
    pub const fn attempt(self) -> AttemptId {
        self.attempt
    }

    /// Returns execution-basis or additional-cause provenance.
    #[must_use]
    pub const fn role(self) -> AttemptAdmissionRole {
        self.role
    }

    /// Returns the policy governing retention for this admission when derivable.
    ///
    /// Version 3 records carry the policy directly. Historical records can
    /// recover it from policy-bearing request causes; proposal-backed version 1
    /// records require repository resolution of the proposal.
    #[must_use]
    pub const fn retention_policy(self) -> Option<CampaignPolicyId> {
        match self.retention_policy {
            Some(policy) => Some(policy),
            None => match self.role {
                AttemptAdmissionRole::ExecutionBasis {
                    cause:
                        BranchRequestCause::ExhaustivePolicy(policy)
                        | BranchRequestCause::ScenarioDefault(policy),
                    ..
                } => Some(policy),
                AttemptAdmissionRole::ExecutionBasis { .. }
                | AttemptAdmissionRole::AdditionalCause { .. } => None,
            },
        }
    }

    /// Returns strict canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes a strict canonical attempt admission.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, invalid, or
    /// oversized bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_exact_record(bytes, "attempt-admission-encoded-bytes")
    }

    /// Returns the exact admission-record identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<AttemptAdmissionId, CampaignCodecError> {
        AttemptAdmissionId::from_content_id(
            crate::ObjectEnvelope::for_record_versioned(
                crate::CampaignRecordKind::AttemptAdmission,
                self.schema_version,
                crate::object::content_children(self.content_children())?,
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        let mut children = vec![("attempt".to_owned(), self.attempt.content_id())];
        match self.role {
            AttemptAdmissionRole::ExecutionBasis {
                proposal: Some(proposal),
                cause,
                ..
            } => {
                children.push(("proposal".to_owned(), proposal.content_id()));
                add_cause_child(&mut children, cause);
            }
            AttemptAdmissionRole::ExecutionBasis {
                proposal: None,
                cause,
                ..
            } => add_cause_child(&mut children, cause),
            AttemptAdmissionRole::AdditionalCause { proposal } => {
                children.push(("proposal".to_owned(), proposal.content_id()));
            }
        }
        if let Some(policy) = self.retention_policy {
            children.push(("retention-policy".to_owned(), policy.content_id()));
        }
        children
    }

    pub(crate) const fn schema_version(&self) -> u32 {
        self.schema_version
    }
}

impl Canonical for AttemptAdmission {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.attempt.encode(encoder);
        self.role.encode(encoder);
        if let Some(policy) = self.retention_policy {
            policy.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        let attempt = AttemptId::decode(decoder)?;
        let role = AttemptAdmissionRole::decode(decoder)?;
        let retention_policy = match schema_version {
            ATTEMPT_ADMISSION_RETENTION_SCHEMA_VERSION => Some(CampaignPolicyId::decode(decoder)?),
            _ => None,
        };
        let scenario_default_basis = matches!(
            role,
            AttemptAdmissionRole::ExecutionBasis {
                cause: BranchRequestCause::ScenarioDefault(_),
                ..
            }
        );
        let compatible = match schema_version {
            RECORD_SCHEMA_VERSION => !scenario_default_basis,
            ATTEMPT_ADMISSION_SCHEMA_VERSION => scenario_default_basis,
            ATTEMPT_ADMISSION_RETENTION_SCHEMA_VERSION => retention_policy.is_some(),
            _ => false,
        };
        if !compatible {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported attempt-admission schema or role",
            });
        }
        Ok(Self {
            schema_version,
            attempt,
            role,
            retention_policy,
        })
    }
}
