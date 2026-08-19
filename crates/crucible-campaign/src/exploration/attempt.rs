//! Branch paths, attempts, and attempt-admission records.

use super::*;

/// Authenticated ordered semantic edge path used for guidance backpropagation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchPath {
    schema_version: u32,
    edges: Vec<BranchEdgeId>,
}

impl BranchPath {
    /// Builds a bounded branch path; an empty path represents genesis discovery.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the path exceeds 65,536 edges.
    pub fn new(edges: Vec<BranchEdgeId>) -> Result<Self, CampaignCodecError> {
        if edges.len() > MAX_BRANCH_PATH_EDGES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "branch-path-edge-count",
            });
        }
        Ok(Self {
            schema_version: RECORD_SCHEMA_VERSION,
            edges,
        })
    }

    /// Returns edges from root to leaf.
    #[must_use]
    pub fn edges(&self) -> &[BranchEdgeId] {
        &self.edges
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
        BranchPathId::from_content_id(
            crate::ObjectEnvelope::for_record(
                crate::CampaignRecordKind::BranchPath,
                BTreeSet::new(),
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }
}

impl Canonical for BranchPath {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.edges.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema(u32::decode(decoder)?)?;
        Self::new(decoder.sequence_bounded(
            MAX_BRANCH_PATH_EDGES,
            "branch-path-edge-count",
            BranchEdgeId::decode,
        )?)
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
