//! Recorded evidence normalization and deterministic failure signatures.

use super::*;

/// Full canonical causal-cone material retained for exact policy keys.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FailureCausalCone {
    pub(in crate::model) canonical_material: String,
}

impl FailureCausalCone {
    /// Builds full causal-cone material from an already-canonical representation.
    #[must_use]
    pub fn from_canonical_material(canonical_material: impl Into<String>) -> Self {
        Self {
            canonical_material: canonical_material.into(),
        }
    }

    /// Returns the full canonical causal-cone material.
    #[must_use]
    pub fn canonical_material(&self) -> &str {
        &self.canonical_material
    }

    /// Returns the hash used by non-exact policy levels when the causal slice is keyed.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::from_canonical_material(FAILURE_CAUSAL_SLICE_DOMAIN, &self.canonical_material)
    }
}

/// Signature-normalization inputs applied before failure fields are keyed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct FailureSignatureNormalization {
    /// Interchangeable-node classes used to canonicalize `faulting_node`.
    pub symmetry_classes: SymmetryReductionClasses,
}

impl FailureSignatureNormalization {
    /// Builds identity normalization with no interchangeable-node classes.
    #[must_use]
    pub fn identity() -> Self {
        Self::default()
    }

    /// Replaces the interchangeable-node classes used by triage canonicalization.
    #[must_use]
    pub fn with_symmetry_classes(mut self, classes: SymmetryReductionClasses) -> Self {
        self.symmetry_classes = classes;
        self
    }
}

/// Deterministic triage-side node relabeling for failure signatures.
///
/// Nodes not assigned to an interchangeable class keep their scenario identity.
/// Nodes inside a class are rewritten to a stable class-local label so symmetric
/// findings on different replicas share one `faulting_node` key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailureSymmetryCanonicalizer {
    pub(in crate::model) coverage_fingerprint: ContentHash,
    pub(in crate::model) classes: SymmetryReductionClasses,
}

impl FailureSymmetryCanonicalizer {
    /// Builds a canonicalizer bound to the recorded coverage fingerprint.
    #[must_use]
    pub fn new(coverage_fingerprint: ContentHash, classes: SymmetryReductionClasses) -> Self {
        Self {
            coverage_fingerprint,
            classes,
        }
    }

    /// Builds an identity canonicalizer for records without symmetry classes.
    #[must_use]
    pub fn identity(coverage_fingerprint: ContentHash) -> Self {
        Self::new(coverage_fingerprint, SymmetryReductionClasses::new())
    }

    /// Returns the recorded coverage fingerprint this canonicalizer is bound to.
    #[must_use]
    pub fn coverage_fingerprint(&self) -> ContentHash {
        self.coverage_fingerprint
    }

    /// Returns `node` under the triage symmetry-canonical relabeling.
    #[must_use]
    pub fn canonical_node(&self, node: &NodeId) -> NodeId {
        match self.classes.classes.get(node) {
            Some(class) => NodeId {
                name: format!("symmetry-class:{}:{}", class.name.len(), class.name),
            },
            None => node.clone(),
        }
    }

    fn canonical_node_option(&self, node: &Option<NodeId>) -> Option<NodeId> {
        node.as_ref().map(|node| self.canonical_node(node))
    }
}

/// Checked event-log evidence for failure-signature construction.
///
/// This value binds the supplied event-log entries to the
/// [`ReproductionEventLogArtifact`] recorded for the same reproduction artifact,
/// and retains the raw entries needed to recheck host-derived violations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailureRecordedEventLog {
    pub(in crate::model) artifact: ContentHash,
    pub(in crate::model) event_log_artifact: ContentHash,
    pub(in crate::model) causal_subsequence: ContentHash,
    pub(in crate::model) causal_subsequence_events: usize,
    pub(in crate::model) coverage_fingerprint: ContentHash,
    pub(in crate::model) evidence_binding: ContentHash,
    pub(in crate::model) projection: EventLogCausalProjection,
    pub(in crate::model) raw_entries: Vec<SchedulerEventLogEntry>,
}

fn failure_recorded_evidence_binding(
    projection: &EventLogCausalProjection,
    coverage_fingerprint: ContentHash,
    recorded_frames: &[Vec<u8>],
) -> ContentHash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"crucible.failure-recorded-evidence.v1\0");
    bytes.extend_from_slice(&projection.content_hash().bytes);
    bytes.extend_from_slice(&coverage_fingerprint.bytes);
    bytes.extend_from_slice(&(recorded_frames.len() as u64).to_le_bytes());
    for frame in recorded_frames {
        bytes.extend_from_slice(&(frame.len() as u64).to_le_bytes());
        bytes.extend_from_slice(frame);
    }
    ContentHash::from_bytes(&bytes)
}

impl FailureRecordedEventLog {
    /// Builds checked signature evidence from retained causal entries and an
    /// independently reconstructed coverage fingerprint.
    ///
    /// This is the adapter boundary used when a remote event stream retains
    /// exact causal events while coverage observations are transported through
    /// the shared coverage-feedback projection.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReplayTargetMismatch`] when the finding's
    /// embedded reproduction identity is inconsistent.
    pub fn from_causal_entries_and_coverage(
        finding: &FindingReproductionArtifact,
        causal_entries: &[SchedulerEventLogEntry],
        coverage_fingerprint: ContentHash,
    ) -> Result<Self, EngineError> {
        Self::from_causal_entries_coverage_and_frames(
            finding,
            causal_entries,
            coverage_fingerprint,
            &[],
        )
    }

    /// Builds checked signature evidence and binds the exact retained frames.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReplayTargetMismatch`] when the finding's
    /// embedded reproduction identity is inconsistent.
    pub fn from_causal_entries_coverage_and_frames(
        finding: &FindingReproductionArtifact,
        causal_entries: &[SchedulerEventLogEntry],
        coverage_fingerprint: ContentHash,
        recorded_frames: &[Vec<u8>],
    ) -> Result<Self, EngineError> {
        validate_finding_static_identity(finding)?;
        let projection = event_log_causal_projection(causal_entries);
        let event_log_artifact = ReproductionEventLogArtifact::from_causal_projection(
            finding.artifact.id(),
            EventLogOffset::new(ContentHash::default(), 0, 0),
            projection.content_hash(),
            projection.canonical_bytes().len(),
            projection.len(),
            coverage_fingerprint,
            Vec::new(),
        );
        Ok(Self {
            artifact: finding.artifact.id(),
            event_log_artifact: event_log_artifact.id(),
            causal_subsequence: projection.content_hash(),
            causal_subsequence_events: projection.len(),
            coverage_fingerprint,
            evidence_binding: failure_recorded_evidence_binding(
                &projection,
                coverage_fingerprint,
                recorded_frames,
            ),
            projection,
            raw_entries: causal_entries.to_vec(),
        })
    }

    /// Builds checked signature evidence from recorded event-log entries.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReplayTargetMismatch`] when `finding`,
    /// `event_log_artifact`, and the supplied `event_log` do not identify the
    /// same reproduction artifact and causal subsequence. Returns
    /// [`EngineError::UnifiedOperationEvidenceMismatch`] when non-hash projection
    /// metadata is inconsistent.
    pub fn from_recorded_artifact(
        finding: &FindingReproductionArtifact,
        event_log_artifact: &ReproductionEventLogArtifact,
        event_log: &[SchedulerEventLogEntry],
    ) -> Result<Self, EngineError> {
        validate_finding_static_identity(finding)?;
        let artifact = finding.artifact.id();
        if event_log_artifact.reproduction_artifact != artifact {
            return Err(EngineError::ReplayTargetMismatch {
                expected: artifact,
                actual: event_log_artifact.reproduction_artifact,
            });
        }

        let projection = event_log_causal_projection(event_log);
        if projection.content_hash() != event_log_artifact.causal_subsequence {
            return Err(EngineError::ReplayTargetMismatch {
                expected: event_log_artifact.causal_subsequence,
                actual: projection.content_hash(),
            });
        }
        if projection.canonical_bytes().len() != event_log_artifact.causal_subsequence_bytes {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-signature.event-log",
                reason: "causal subsequence byte length does not match recorded metadata",
            });
        }
        if projection.len() != event_log_artifact.causal_subsequence_events {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-signature.event-log",
                reason: "causal subsequence event count does not match recorded metadata",
            });
        }
        let coverage_fingerprint = coverage_fingerprint_from_event_log(event_log);
        if coverage_fingerprint != event_log_artifact.coverage_fingerprint {
            return Err(EngineError::ReplayTargetMismatch {
                expected: event_log_artifact.coverage_fingerprint,
                actual: coverage_fingerprint,
            });
        }

        Ok(Self {
            artifact,
            event_log_artifact: event_log_artifact.id(),
            causal_subsequence: projection.content_hash(),
            causal_subsequence_events: projection.len(),
            coverage_fingerprint: event_log_artifact.coverage_fingerprint,
            evidence_binding: failure_recorded_evidence_binding(
                &projection,
                event_log_artifact.coverage_fingerprint,
                &[],
            ),
            projection,
            raw_entries: event_log.to_vec(),
        })
    }

    /// Returns the reproduction artifact this checked log belongs to.
    #[must_use]
    pub fn artifact(&self) -> ContentHash {
        self.artifact
    }

    /// Returns the content address of the event-log metadata record.
    #[must_use]
    pub fn event_log_artifact(&self) -> ContentHash {
        self.event_log_artifact
    }

    /// Returns the recorded causal-subsequence hash.
    #[must_use]
    pub fn causal_subsequence(&self) -> ContentHash {
        self.causal_subsequence
    }

    /// Returns the number of causal events retained by the projection.
    #[must_use]
    pub fn causal_subsequence_events(&self) -> usize {
        self.causal_subsequence_events
    }

    /// Returns the recorded deterministic coverage fingerprint validated against the log.
    #[must_use]
    pub fn coverage_fingerprint(&self) -> ContentHash {
        self.coverage_fingerprint
    }

    /// Returns the binding over causal evidence, coverage, and retained frames.
    #[must_use]
    pub fn evidence_binding(&self) -> ContentHash {
        self.evidence_binding
    }

    /// Returns the bucketed failure coverage class for this recorded log.
    #[must_use]
    pub fn coverage_class(&self) -> FailureCoverageClass {
        FailureCoverageClass::from_coverage_fingerprint(self.coverage_fingerprint)
    }

    /// Builds a symmetry canonicalizer bound to this log's recorded coverage.
    #[must_use]
    pub fn symmetry_canonicalizer(
        &self,
        normalization: &FailureSignatureNormalization,
    ) -> FailureSymmetryCanonicalizer {
        FailureSymmetryCanonicalizer::new(
            self.coverage_fingerprint,
            normalization.symmetry_classes.clone(),
        )
    }
}

/// Property-violation source record consumed by failure-signature construction.
///
/// This wraps the deterministic host assertion violation record. The signature
/// constructor reads the property id, quantifier, node, and site kind from this
/// value rather than replaying the guest.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailurePropertyViolationRecord {
    /// Deterministic assertion violation produced from the retained assertion log.
    pub violation: HostAssertionViolation,
}

impl FailurePropertyViolationRecord {
    /// Builds a signature input record from an assertion violation.
    #[must_use]
    pub fn new(violation: HostAssertionViolation) -> Self {
        Self { violation }
    }

    /// Returns the property key read from the violation record.
    #[must_use]
    pub fn property_key(&self) -> FailurePropertyKey {
        FailurePropertyKey {
            id: self.violation.assertion.clone(),
            quantifier: self.violation.quantifier,
        }
    }

    /// Returns the first failing point read from the violation record.
    #[must_use]
    pub fn first_failing_point(&self) -> FailureFirstFailingPoint {
        self.first_failing_point_with(&FailureSymmetryCanonicalizer::identity(
            ContentHash::default(),
        ))
    }

    /// Returns the first failing point under the supplied symmetry relabeling.
    #[must_use]
    pub fn first_failing_point_with(
        &self,
        canonicalizer: &FailureSymmetryCanonicalizer,
    ) -> FailureFirstFailingPoint {
        FailureFirstFailingPoint {
            event_kind: self.violation.event_kind.clone(),
            faulting_node: canonicalizer.canonical_node_option(&self.violation.node),
        }
    }
}

/// Engine-owned timeout evidence consumed by failure-signature construction.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailureTimeoutRecord {
    /// Deterministic budget domain that stopped the run.
    pub budget_kind: FailureTimeoutBudgetKind,
    /// Configured budget limit, when the producer exposes one.
    pub configured_limit: Option<u64>,
    /// Scheduler quanta observed at the terminal boundary.
    pub observed_quanta: u64,
    /// Virtual time observed at the terminal boundary.
    pub at_virtual_time: VirtualTime,
    /// Retired instruction count at the boundary, when node-local evidence exists.
    pub at_icount: Option<Icount>,
    /// Node attributed to the boundary, when node-local evidence exists.
    pub node: Option<NodeId>,
    /// Stable event kind anchoring the timeout in the recorded causal log.
    pub event_kind: String,
    /// Content-addressed reproduction artifact for this run.
    pub reproduction_artifact: ContentHash,
}

impl FailureTimeoutRecord {
    /// Builds timeout evidence for an engine-owned execution-budget boundary.
    #[must_use]
    pub fn new(
        budget_kind: FailureTimeoutBudgetKind,
        configured_limit: Option<u64>,
        observed_quanta: u64,
        at_virtual_time: VirtualTime,
        at_icount: Option<Icount>,
        node: Option<NodeId>,
        reproduction_artifact: ContentHash,
    ) -> Self {
        Self {
            budget_kind,
            configured_limit,
            observed_quanta,
            at_virtual_time,
            at_icount,
            node,
            event_kind: String::from("execution_budget_exhausted"),
            reproduction_artifact,
        }
    }

    /// Returns the first attributable point recorded for this timeout.
    #[must_use]
    pub fn first_failing_point(&self) -> FailureFirstFailingPoint {
        self.first_failing_point_with(&FailureSymmetryCanonicalizer::identity(
            ContentHash::default(),
        ))
    }

    /// Returns the first attributable point under a symmetry relabeling.
    #[must_use]
    pub fn first_failing_point_with(
        &self,
        canonicalizer: &FailureSymmetryCanonicalizer,
    ) -> FailureFirstFailingPoint {
        FailureFirstFailingPoint {
            event_kind: self.event_kind.clone(),
            faulting_node: canonicalizer.canonical_node_option(&self.node),
        }
    }
}

/// Deterministic, content-addressed root-cause signature for one finding.
///
/// The tuple is computed from stored finding artifacts, violation records, and
/// recorded event-log projections only. It deliberately omits discovery path,
/// discovering campaign, finding fingerprint, wall-clock data, and raw
/// observational log entries.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailureSignature {
    /// Closed failure kind for this finding.
    pub failure_kind: FailureKind,
    /// Violated property identity for property failures, or `None` for divergence.
    pub property: Option<FailurePropertyKey>,
    /// First attributable point read from the violation record or bisection point.
    pub first_failing_point: FailureFirstFailingPoint,
    /// Bucketed class derived from the deterministic coverage fingerprint.
    pub coverage_class: FailureCoverageClass,
    /// Discovery-evidence binding checked during offline recomputation.
    pub evidence_binding: ContentHash,
    /// Optional digest of the cone-scoped recorded causal slice.
    ///
    /// This is computed over the causal prefix ending at the first failing
    /// causal entry, not the whole causal subsequence.
    pub causal_slice_hash: Option<ContentHash>,
    /// Full canonical causal cone retained for exact-policy forensic keys.
    ///
    /// Coarse/default/fine policies key only selected scalar fields and, for
    /// fine, the cone hash above. The exact policy uses this material directly.
    pub causal_cone: Option<FailureCausalCone>,
    /// Absolute instruction count of the first failing point for reports only.
    ///
    /// The current default content hash excludes this value so minimization that
    /// shifts absolute icounts does not perturb the clustering key.
    pub at_icount_report_only: Option<Icount>,
}

impl FailureSignature {
    /// Builds a property-violation signature from recorded artifacts only.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReplayTargetMismatch`] if the finding's embedded
    /// artifact, event-log metadata, violation record, replay metadata, and
    /// configuration id disagree before any signature field is read.
    pub fn from_recorded_property_violation(
        finding: &FindingReproductionArtifact,
        event_log: &FailureRecordedEventLog,
        violation: &FailurePropertyViolationRecord,
    ) -> Result<Self, EngineError> {
        Self::from_recorded_property_violation_with_normalization(
            finding,
            event_log,
            violation,
            &FailureSignatureNormalization::identity(),
        )
    }

    /// Builds a property-violation signature with explicit normalizations.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReplayTargetMismatch`] if the finding's embedded
    /// artifact, event-log metadata, violation record, replay metadata, and
    /// configuration id disagree before any signature field is read. Returns
    /// [`EngineError::UnifiedOperationEvidenceMismatch`] when neither a causal
    /// assertion transition nor an exact host-checked violation exists in the
    /// retained log.
    pub fn from_recorded_property_violation_with_normalization(
        finding: &FindingReproductionArtifact,
        event_log: &FailureRecordedEventLog,
        violation: &FailurePropertyViolationRecord,
        normalization: &FailureSignatureNormalization,
    ) -> Result<Self, EngineError> {
        validate_finding_static_identity(finding)?;
        validate_recorded_event_log_for_finding(finding, event_log)?;
        validate_violation_for_finding(finding, violation)?;
        let canonicalizer = event_log.symmetry_canonicalizer(normalization);
        let causal_cone = match validate_violation_point(event_log, violation) {
            Ok(causal_index) => {
                failure_causal_cone_through_index(event_log, causal_index, &canonicalizer)
            }
            Err(_) => validated_host_violation_cone(finding, event_log, violation, &canonicalizer)?,
        };
        Ok(Self {
            failure_kind: FailureKind::PropertyViolation,
            property: Some(violation.property_key()),
            first_failing_point: violation.first_failing_point_with(&canonicalizer),
            coverage_class: event_log.coverage_class(),
            evidence_binding: event_log.evidence_binding(),
            causal_slice_hash: Some(causal_cone.content_hash()),
            causal_cone: Some(causal_cone),
            at_icount_report_only: violation.violation.at_icount,
        })
    }

    /// Builds a divergence signature from a recorded bisection point.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReplayTargetMismatch`] if the finding's embedded
    /// artifact, event-log metadata, replay metadata, and configuration id
    /// disagree before any signature field is read. Returns
    /// [`EngineError::UnifiedOperationEvidenceMismatch`] when `divergence` is not
    /// present in the checked recorded causal projection.
    pub fn from_recorded_divergence(
        finding: &FindingReproductionArtifact,
        event_log: &FailureRecordedEventLog,
        divergence: &EventLogCausalDivergencePoint,
    ) -> Result<Self, EngineError> {
        Self::from_recorded_divergence_with_normalization(
            finding,
            event_log,
            divergence,
            &FailureSignatureNormalization::identity(),
        )
    }

    /// Builds a divergence signature with explicit normalizations.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReplayTargetMismatch`] if the finding's embedded
    /// artifact, event-log metadata, replay metadata, and configuration id
    /// disagree before any signature field is read. Returns
    /// [`EngineError::UnifiedOperationEvidenceMismatch`] when `divergence` is not
    /// present in the checked recorded causal projection.
    pub fn from_recorded_divergence_with_normalization(
        finding: &FindingReproductionArtifact,
        event_log: &FailureRecordedEventLog,
        divergence: &EventLogCausalDivergencePoint,
        normalization: &FailureSignatureNormalization,
    ) -> Result<Self, EngineError> {
        validate_finding_static_identity(finding)?;
        validate_recorded_event_log_for_finding(finding, event_log)?;
        let canonicalizer = event_log.symmetry_canonicalizer(normalization);
        let causal_index = validate_divergence_point(event_log, divergence)?;
        let causal_cone =
            failure_causal_cone_through_index(event_log, causal_index, &canonicalizer);
        Ok(Self {
            failure_kind: FailureKind::Divergence,
            property: None,
            first_failing_point: FailureFirstFailingPoint {
                event_kind: divergence.kind.clone(),
                faulting_node: canonicalizer
                    .canonical_node_option(&divergence_faulting_node(divergence)),
            },
            coverage_class: event_log.coverage_class(),
            evidence_binding: event_log.evidence_binding(),
            causal_slice_hash: Some(causal_cone.content_hash()),
            causal_cone: Some(causal_cone),
            at_icount_report_only: Some(divergence.at.icount),
        })
    }

    /// Builds a timeout signature from recorded execution-budget evidence.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReplayTargetMismatch`] when the finding, event
    /// log, or timeout record names a different reproduction artifact. Returns
    /// [`EngineError::UnifiedOperationEvidenceMismatch`] when the timeout
    /// boundary is absent from the checked causal projection.
    pub fn from_recorded_timeout(
        finding: &FindingReproductionArtifact,
        event_log: &FailureRecordedEventLog,
        timeout: &FailureTimeoutRecord,
    ) -> Result<Self, EngineError> {
        Self::from_recorded_timeout_with_normalization(
            finding,
            event_log,
            timeout,
            &FailureSignatureNormalization::identity(),
        )
    }

    /// Builds a timeout signature with explicit symmetry normalization.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReplayTargetMismatch`] when the finding, event
    /// log, or timeout record names a different reproduction artifact. Returns
    /// [`EngineError::UnifiedOperationEvidenceMismatch`] when the exact timeout
    /// boundary is absent from the checked causal projection.
    pub fn from_recorded_timeout_with_normalization(
        finding: &FindingReproductionArtifact,
        event_log: &FailureRecordedEventLog,
        timeout: &FailureTimeoutRecord,
        normalization: &FailureSignatureNormalization,
    ) -> Result<Self, EngineError> {
        validate_finding_static_identity(finding)?;
        validate_recorded_event_log_for_finding(finding, event_log)?;
        if timeout.reproduction_artifact != finding.artifact.id() {
            return Err(EngineError::ReplayTargetMismatch {
                expected: finding.artifact.id(),
                actual: timeout.reproduction_artifact,
            });
        }
        let causal_index = validate_timeout_point(event_log, timeout)?;
        let canonicalizer = event_log.symmetry_canonicalizer(normalization);
        let causal_cone =
            failure_causal_cone_through_index(event_log, causal_index, &canonicalizer);
        Ok(Self {
            failure_kind: FailureKind::Timeout,
            property: None,
            first_failing_point: timeout.first_failing_point_with(&canonicalizer),
            coverage_class: event_log.coverage_class(),
            evidence_binding: event_log.evidence_binding(),
            causal_slice_hash: Some(causal_cone.content_hash()),
            causal_cone: Some(causal_cone),
            at_icount_report_only: timeout.at_icount,
        })
    }

    /// Returns the deterministic content address of this signature tuple.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::from_canonical_material(FAILURE_SIGNATURE_DOMAIN, &self.canonical_material())
    }

    /// Returns the canonical material hashed by [`Self::content_hash`].
    #[must_use]
    pub fn canonical_material(&self) -> String {
        failure_signature_material(self)
    }

    /// Returns canonical report material including non-key detail fields.
    #[must_use]
    pub fn report_material(&self) -> String {
        failure_signature_report_material(self)
    }

    /// Projects this signature into the key selected by `policy`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::UnifiedOperationEvidenceMismatch`] if the
    /// signature's coverage bucket does not match the policy's fixed bucketing
    /// algorithm, or if the exact policy needs missing causal-cone material.
    pub fn signature_key(
        &self,
        policy: SignaturePolicy,
    ) -> Result<FailureSignatureKey, EngineError> {
        policy.signature_key(self)
    }
}
