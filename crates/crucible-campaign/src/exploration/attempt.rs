//! Branch paths, attempts, and attempt-admission records.

use super::*;

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

/// Explicit discovery or one-selection branch execution start.
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
        Ok(Self {
            schema_version: RECORD_SCHEMA_VERSION,
            start,
            path,
            stop,
        })
    }

    /// Returns discovery or branch start semantics.
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
            crate::ObjectEnvelope::for_record(
                crate::CampaignRecordKind::Attempt,
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
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema(u32::decode(decoder)?)?;
        Self::new(
            AttemptStart::decode(decoder)?,
            BranchPathId::decode(decoder)?,
            StopCondition::decode(decoder)?,
        )
    }
}

/// Unique execution basis or an additional deduplicated proposal cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttemptAdmissionRole {
    /// The one cause that spends attempt budget and fixes estimator provenance.
    ExecutionBasis {
        /// Proposal, absent only for discovery.
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
}

impl AttemptAdmission {
    /// Builds an attempt admission record.
    #[must_use]
    pub const fn new(attempt: AttemptId, role: AttemptAdmissionRole) -> Self {
        Self {
            schema_version: RECORD_SCHEMA_VERSION,
            attempt,
            role,
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
            crate::ObjectEnvelope::for_record(
                crate::CampaignRecordKind::AttemptAdmission,
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
        children
    }
}

impl Canonical for AttemptAdmission {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.attempt.encode(encoder);
        self.role.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema(u32::decode(decoder)?)?;
        Ok(Self::new(
            AttemptId::decode(decoder)?,
            AttemptAdmissionRole::decode(decoder)?,
        ))
    }
}
