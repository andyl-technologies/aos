//! Bounded diagnostic exports built from checked inputs and protected timelines.
//!
//! The diagnostic envelope keeps offline-replay inputs only when the caller has
//! independently authorized deployment disclosure. Both audiences retain exact
//! plan commitments, artifact content identities, available persisted recovery
//! timing, and closed event kinds. The timeline has no fields for adapter
//! request payloads, provider evidence, or free-form runtime messages.
//! Deployment exports may embed checked inputs, including planned resource
//! identities; redacted exports withhold those inputs.
//!
//! Timeline construction checks retained record shape and plan membership. It
//! neither authenticates the supplying journal nor observes current runtime
//! state, and it never synthesizes events absent from the supplied history.
//!
//! ```json
//! {
//!   "schema": "aos.ability.diagnostic-bundle/v1",
//!   "required_features": [],
//!   "inspection_bundle": "sha256:<inspection-bundle-digest>",
//!   "plan": "sha256:<effect-plan-digest>",
//!   "binding_plan": "sha256:<binding-plan-digest>",
//!   "audience": "redacted",
//!   "inputs": { "disclosure": "redacted" },
//!   "artifacts": [],
//!   "timeline": {
//!     "plan": "sha256:<effect-plan-digest>",
//!     "audience": "redacted",
//!     "provenance": { "status": "unverified-retained-records" },
//!     "transaction": { "disclosure": "redacted" },
//!     "pending_state": "unavailable",
//!     "pending": [],
//!     "events": []
//!   },
//!   "offline_replay": "inputs-redacted",
//!   "limitations": [
//!     "commitment-correlation-retained",
//!     "normalized-inputs-redacted",
//!     "execution-topology-redacted",
//!     "artifact-locations-redacted",
//!     "execution-evidence-redacted",
//!     "native-execution-qualification-not-included",
//!     "pending-dependency-state-unavailable",
//!     "execution-record-provenance-unverified",
//!     "journal-authentication-not-verified",
//!     "retained-records-not-live-observation",
//!     "offline-replay-inputs-redacted"
//!   ]
//! }
//! ```

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::num::{NonZeroU32, NonZeroU64};

use aos_ability_model::{
    ABILITY_LIMITS_V1, LocalKey, OperationId, PlanId, PlanNodeKey, RequiredFeature, TransactionId,
};
use aos_ability_validate::CheckedEffectPlan;
use aos_contract::Sha256Digest;
use aos_contract::limits::JsonLimits;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CheckedInspectionBundle, INSPECTION_BUNDLE_MAX_BYTES, InspectionBundle, InspectionBundleError,
    ProtectedValue,
};

/// Exact schema discriminator for one exportable diagnostic bundle.
pub const DIAGNOSTIC_BUNDLE_SCHEMA: &str = "aos.ability.diagnostic-bundle/v1";

/// Maximum encoded byte length of one diagnostic bundle.
pub const DIAGNOSTIC_BUNDLE_MAX_BYTES: usize =
    INSPECTION_BUNDLE_MAX_BYTES.saturating_add(ABILITY_LIMITS_V1.max_document_bytes as usize);

const DIAGNOSTIC_BUNDLE_COMPONENT_LIMIT: usize = 12;

/// Selects which deployment details the caller chooses to disclose.
///
/// This selection does not authenticate or authorize a reader. A frontend must
/// enforce deployment access before selecting [`Self::Deployment`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticBundleAudience {
    /// Retains checked inputs, topology identities, and artifact locations.
    Deployment,
    /// Removes deployment topology while retaining stable ordinals and commitments.
    Redacted,
}

/// One exact artifact identity with an audience-controlled store location.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticArtifact {
    /// Identifies the artifact's exact bytes or canonical semantic content.
    pub content: Sha256Digest,
    /// Preserves the artifact's NAR identity.
    pub nar_hash: Sha256Digest,
    /// Identifies the authenticated transitive closure association.
    pub closure: Sha256Digest,
    /// Retains the selected Nix store path only for deployment disclosure.
    pub store_path: ProtectedValue<String>,
}

/// Names a privacy or replay limit carried by a diagnostic export.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticLimitation {
    /// Exact commitments and ordinals may correlate the export with a deployment.
    CommitmentCorrelationRetained,
    /// Normalized planning and validation inputs were withheld.
    NormalizedInputsRedacted,
    /// Transaction and operation identities were withheld.
    ExecutionTopologyRedacted,
    /// Artifact store locations were withheld while content identities remained.
    ArtifactLocationsRedacted,
    /// Adapter requests, outputs, and provider evidence are absent by design.
    ExecutionEvidenceRedacted,
    /// Native sidecar policy and resource-map qualification are not embedded.
    NativeExecutionQualificationNotIncluded,
    /// The source did not supply retained pending-dependency claims.
    PendingDependencyStateUnavailable,
    /// No independently selected journal anchor was supplied with the records.
    ExecutionRecordProvenanceUnverified,
    /// This portable export does not verify journal authentication.
    JournalAuthenticationNotVerified,
    /// Retained records do not establish the current state of a live runtime.
    RetainedRecordsNotLiveObservation,
    /// Bytes from an incomplete final frame are absent from the exported timeline.
    IncompleteJournalTailExcluded,
    /// Pure offline replay cannot proceed without separately supplied exact inputs.
    OfflineReplayInputsRedacted,
}

/// Reports whether this export alone contains the pure inputs needed for replay.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReplayAvailability {
    /// The exact canonical inspection inputs are embedded.
    Available,
    /// Inputs were redacted and must be supplied from an authorized source.
    InputsRedacted,
}

/// Labels the caller-established provenance of retained timeline records.
///
/// The portable constructor validates record shape and plan linkage. It does
/// not authenticate a journal. A supplied digest is only a caller assertion
/// about an externally selected journal anchor, not proof of authentication.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TimelineProvenance {
    /// The records have no independently authenticated journal anchor.
    UnverifiedRetainedRecords,
    /// The caller reports the exact journal anchor it selected externally.
    CallerAssertedJournalAnchor {
        /// Identifies the exact journal selected by the caller.
        journal: Sha256Digest,
    },
    /// The caller reports an exact verified prefix and an incomplete final frame.
    CallerAssertedJournalPrefix {
        /// Identifies the last complete frame in the selected journal.
        journal: Sha256Digest,
        /// Counts trailing bytes excluded because they do not form a complete frame.
        incomplete_tail_bytes: NonZeroU64,
    },
}

/// Carries only timing that retained records establish across executor restarts.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "availability", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TimelineTiming {
    /// The retained source does not establish recovery timing for this event.
    Unavailable,
    /// The retained source establishes consumed recovery budget for one operation.
    OperationRecoveryElapsed {
        /// Gives persisted operation recovery time consumed through this event.
        elapsed_millis: u64,
    },
}

/// Classifies one redaction-safe point in an operation timeline.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimelineEventKind {
    /// The transaction and its recovery roots became durable.
    TransactionPlanned,
    /// Fresh authority and resources admitted an operation attempt.
    OperationAdmitted,
    /// A durable retry delay was scheduled.
    RetryScheduled,
    /// A durable retry delay elapsed.
    RetryReady,
    /// Intent became durable before an external effect.
    EffectStarted,
    /// Provider evidence established successful completion.
    EffectCompleted,
    /// Provider evidence established rejection before any effect.
    RejectedBeforeEffect,
    /// The runtime cancelled dispatch before calling the provider.
    DispatchCancelled,
    /// The runtime deadline expired before provider dispatch.
    DispatchTimedOut,
    /// An external effect may have occurred.
    EffectIndeterminate,
    /// Observation of an indeterminate effect started.
    ReconciliationStarted,
    /// Observation established completion.
    ReconciledCompleted,
    /// Observation established rejection before effect.
    ReconciledRejectedBeforeEffect,
    /// Observation established that a retry is safe.
    ReconciledSafeToRetry,
    /// Observation remained inconclusive.
    ReconciliationStillIndeterminate,
    /// Observation requires an operator decision.
    ReconciliationInterventionRequired,
    /// Cancellation of an in-flight effect started.
    CancellationStarted,
    /// Cancellation established that no effect occurred.
    CancellationRejectedBeforeEffect,
    /// Cancellation observed completion of the original effect.
    CancellationObservedCompletion,
    /// Cancellation left the effect indeterminate.
    CancellationIndeterminate,
    /// Compensation was requested for a completed operation.
    CompensationRequested,
    /// Fresh authority and resources admitted compensation.
    CompensationAdmitted,
    /// Compensation intent became durable.
    CompensationStarted,
    /// Compensation completed successfully.
    CompensationCompleted,
    /// Compensation was rejected before any effect.
    CompensationRejectedBeforeEffect,
    /// A compensation effect may have occurred.
    CompensationIndeterminate,
    /// Observation of indeterminate compensation started.
    CompensationReconciliationStarted,
    /// Compensation observation established completion.
    CompensationReconciledCompleted,
    /// Compensation observation established rejection before effect.
    CompensationReconciledRejectedBeforeEffect,
    /// Compensation observation established that a retry is safe.
    CompensationReconciledSafeToRetry,
    /// Compensation observation remained inconclusive.
    CompensationReconciliationStillIndeterminate,
    /// Compensation observation requires an operator decision.
    CompensationReconciliationInterventionRequired,
    /// Compensation stopped and requires an operator decision.
    CompensationInterventionRequired,
    /// A checked branch alternative was selected.
    BranchSelected,
    /// A branch selection excluded an operation.
    OperationSkipped,
    /// A checked conditional merge exposed its outputs.
    MergeCompleted,
    /// Held resources were safely released.
    ResourcesReleased,
    /// Responsibility for unresolved resources was transferred or fenced.
    OwnershipTransferred,
    /// The operation settled unsuccessfully without pending recovery.
    SettledFailure,
}

impl TimelineEventKind {
    const fn subject_kind(self) -> Option<TimelineSubjectKind> {
        match self {
            Self::TransactionPlanned => None,
            Self::BranchSelected => Some(TimelineSubjectKind::Decision),
            Self::MergeCompleted => Some(TimelineSubjectKind::Merge),
            _ => Some(TimelineSubjectKind::Operation),
        }
    }

    const fn attempt_requirement(self) -> AttemptRequirement {
        match self {
            Self::OperationAdmitted
            | Self::RetryScheduled
            | Self::RetryReady
            | Self::EffectStarted
            | Self::EffectCompleted
            | Self::RejectedBeforeEffect
            | Self::DispatchCancelled
            | Self::DispatchTimedOut
            | Self::EffectIndeterminate
            | Self::ReconciliationStarted
            | Self::ReconciledCompleted
            | Self::ReconciledRejectedBeforeEffect
            | Self::ReconciledSafeToRetry
            | Self::ReconciliationStillIndeterminate
            | Self::ReconciliationInterventionRequired
            | Self::CancellationStarted
            | Self::CancellationRejectedBeforeEffect
            | Self::CancellationObservedCompletion
            | Self::CancellationIndeterminate => AttemptRequirement::Required,
            Self::SettledFailure => AttemptRequirement::Optional,
            _ => AttemptRequirement::Forbidden,
        }
    }

    const fn timing_requirement(self) -> TimingRequirement {
        match self {
            Self::TransactionPlanned
            | Self::BranchSelected
            | Self::OperationSkipped
            | Self::MergeCompleted => TimingRequirement::Unavailable,
            _ => TimingRequirement::OperationRecoveryElapsed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TimelineSubjectKind {
    Operation,
    Decision,
    Merge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttemptRequirement {
    Forbidden,
    Optional,
    Required,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TimingRequirement {
    Unavailable,
    OperationRecoveryElapsed,
}

/// Supplies one retained claim that an operation was waiting on dependencies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingOperationInput {
    /// Identifies the exact checked operation.
    pub operation: OperationId,
    /// Counts incomplete data, success, ordering, or readiness predecessors.
    pub blocking_dependencies: usize,
}

/// Supplies one retained event record after private values have been discarded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimelineEventInput {
    /// Preserves the claimed durable journal sequence.
    pub sequence: u64,
    /// Carries one closed event classification.
    pub kind: TimelineEventKind,
    /// Identifies the affected checked node, or is absent for transaction events.
    pub node: Option<PlanNodeKey>,
    /// Identifies the primary operation attempt when the runtime event has one.
    pub attempt: Option<NonZeroU32>,
    /// Names the alternative carried by a durable branch-selection event.
    pub selected_alternative: Option<LocalKey>,
    /// Retains persisted operation recovery timing when the source establishes it.
    pub timing: TimelineTiming,
}

/// States whether retained pending-dependency claims were supplied.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PendingStateAvailability {
    /// No pending-dependency state was supplied by the source.
    Unavailable,
    /// The source supplied its retained pending-dependency claims.
    RetainedClaims,
}

/// Describes one pending operation without exposing its private identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingOperationView {
    operation_ordinal: usize,
    operation: ProtectedValue<OperationId>,
    blocking_dependencies: usize,
}

impl PendingOperationView {
    /// Returns the operation's zero-based position in checked plan order.
    #[must_use]
    pub const fn operation_ordinal(&self) -> usize {
        self.operation_ordinal
    }

    /// Returns the exact operation identity or its redaction marker.
    #[must_use]
    pub const fn operation(&self) -> &ProtectedValue<OperationId> {
        &self.operation
    }

    /// Returns the number of incomplete checked predecessors.
    #[must_use]
    pub const fn blocking_dependencies(&self) -> usize {
        self.blocking_dependencies
    }
}

/// Describes one retained event claim without request payloads, outputs, or evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TimelineEvent {
    sequence: u64,
    kind: TimelineEventKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    node_ordinal: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    node: Option<ProtectedValue<PlanNodeKey>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempt: Option<NonZeroU32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_alternative_ordinal: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_alternative: Option<ProtectedValue<LocalKey>>,
    timing: TimelineTiming,
}

impl TimelineEvent {
    /// Returns the claimed durable journal sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the closed redaction-safe event classification.
    #[must_use]
    pub const fn kind(&self) -> TimelineEventKind {
        self.kind
    }

    /// Returns the checked-plan node ordinal for node-scoped events.
    #[must_use]
    pub const fn node_ordinal(&self) -> Option<usize> {
        self.node_ordinal
    }

    /// Returns an exact node identity, its marker, or `None` for transaction events.
    #[must_use]
    pub const fn node(&self) -> Option<&ProtectedValue<PlanNodeKey>> {
        self.node.as_ref()
    }

    /// Returns the primary attempt number when the source event carries one.
    #[must_use]
    pub const fn attempt(&self) -> Option<NonZeroU32> {
        self.attempt
    }

    /// Returns the selected alternative's position in checked decision order.
    #[must_use]
    pub const fn selected_alternative_ordinal(&self) -> Option<usize> {
        self.selected_alternative_ordinal
    }

    /// Returns the exact selected alternative, its marker, or `None` otherwise.
    #[must_use]
    pub const fn selected_alternative(&self) -> Option<&ProtectedValue<LocalKey>> {
        self.selected_alternative.as_ref()
    }

    /// Returns only timing established by the retained source.
    #[must_use]
    pub const fn timing(&self) -> TimelineTiming {
        self.timing
    }
}

/// Owns a bounded transaction timeline with stable plan ordinals.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionTimeline {
    plan: PlanId,
    audience: DiagnosticBundleAudience,
    provenance: TimelineProvenance,
    transaction: ProtectedValue<TransactionId>,
    pending_state: PendingStateAvailability,
    pending: Vec<PendingOperationView>,
    events: Vec<TimelineEvent>,
}

impl ExecutionTimeline {
    /// Constructs a bounded timeline from already value-free retained records.
    ///
    /// The constructor validates plan linkage, event order, checked node
    /// membership, and event-subject shape before applying identity redaction.
    /// It preserves exactly the supplied events and does not infer missing
    /// history. Callers must authenticate the retained journal separately.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown pending operations, unknown event nodes,
    /// non-increasing sequences, decreasing elapsed times, malformed event
    /// subjects, or a version-1 collection limit violation.
    pub fn from_records(
        transaction: TransactionId,
        plan: &CheckedEffectPlan,
        pending_state: PendingStateAvailability,
        pending: Vec<PendingOperationInput>,
        events: Vec<TimelineEventInput>,
        provenance: TimelineProvenance,
        audience: DiagnosticBundleAudience,
    ) -> Result<Self, DiagnosticBundleError> {
        let node_ordinals = node_ordinals(plan)?;
        if pending.len() > ABILITY_LIMITS_V1.max_graph_nodes as usize
            || events.len() > ABILITY_LIMITS_V1.max_graph_edges as usize
        {
            return Err(DiagnosticBundleError::ItemLimit);
        }
        if pending_state == PendingStateAvailability::Unavailable && !pending.is_empty() {
            return Err(DiagnosticBundleError::InvalidPendingState);
        }

        let mut pending = pending
            .into_iter()
            .map(|entry| {
                if entry.operation.plan != plan.id() {
                    return Err(DiagnosticBundleError::UnknownOperation);
                }
                if entry.blocking_dependencies > ABILITY_LIMITS_V1.max_graph_edges as usize {
                    return Err(DiagnosticBundleError::ItemLimit);
                }
                let operation_node = PlanNodeKey::Operation {
                    key: entry.operation.operation.clone(),
                };
                let operation_ordinal = node_ordinals
                    .get(&operation_node)
                    .copied()
                    .ok_or(DiagnosticBundleError::UnknownOperation)?;
                Ok(PendingOperationView {
                    operation_ordinal,
                    operation: protect(entry.operation, audience),
                    blocking_dependencies: entry.blocking_dependencies,
                })
            })
            .collect::<Result<Vec<_>, DiagnosticBundleError>>()?;
        pending.sort_by_key(PendingOperationView::operation_ordinal);
        if pending
            .windows(2)
            .any(|pair| pair[0].operation_ordinal == pair[1].operation_ordinal)
        {
            return Err(DiagnosticBundleError::DuplicatePendingOperation);
        }

        if events
            .windows(2)
            .any(|pair| pair[0].sequence >= pair[1].sequence)
        {
            return Err(DiagnosticBundleError::NoncanonicalEventOrder);
        }
        let events = events
            .into_iter()
            .map(|event| timeline_event(event, plan, &node_ordinals, audience))
            .collect::<Result<Vec<_>, _>>()?;

        let timeline = Self {
            plan: plan.id(),
            audience,
            provenance,
            transaction: protect(transaction, audience),
            pending_state,
            pending,
            events,
        };
        timeline.validate(audience, Some(plan))?;
        Ok(timeline)
    }

    /// Returns the exact checked effect-plan identity.
    #[must_use]
    pub const fn plan(&self) -> PlanId {
        self.plan
    }

    /// Returns the caller-selected disclosure audience.
    #[must_use]
    pub const fn audience(&self) -> DiagnosticBundleAudience {
        self.audience
    }

    /// Returns the caller-established retained-record provenance label.
    #[must_use]
    pub const fn provenance(&self) -> TimelineProvenance {
        self.provenance
    }

    /// Returns the transaction identity or its explicit redaction marker.
    #[must_use]
    pub const fn transaction(&self) -> &ProtectedValue<TransactionId> {
        &self.transaction
    }

    /// Reports whether the source supplied pending-dependency claims.
    #[must_use]
    pub const fn pending_state(&self) -> PendingStateAvailability {
        self.pending_state
    }

    /// Returns retained claims about operations waiting for checked predecessors.
    #[must_use]
    pub fn pending(&self) -> &[PendingOperationView] {
        &self.pending
    }

    /// Returns supplied event records in strictly increasing claimed journal order.
    #[must_use]
    pub fn events(&self) -> &[TimelineEvent] {
        &self.events
    }

    fn validate(
        &self,
        audience: DiagnosticBundleAudience,
        plan: Option<&CheckedEffectPlan>,
    ) -> Result<(), DiagnosticBundleError> {
        if plan.is_some_and(|plan| plan.id() != self.plan) {
            return Err(DiagnosticBundleError::PlanMismatch);
        }
        if self.audience != audience || !protected_matches_audience(&self.transaction, audience) {
            return Err(DiagnosticBundleError::InvalidDisclosure);
        }
        if self.pending.len() > ABILITY_LIMITS_V1.max_graph_nodes as usize
            || self.events.len() > ABILITY_LIMITS_V1.max_graph_edges as usize
        {
            return Err(DiagnosticBundleError::ItemLimit);
        }
        if self.pending_state == PendingStateAvailability::Unavailable && !self.pending.is_empty() {
            return Err(DiagnosticBundleError::InvalidPendingState);
        }

        let nodes = plan.map(checked_nodes).transpose()?;
        let operation_count = plan.map_or(0, |plan| plan.document().operations.len());
        let mut previous_pending_ordinal = None;
        for pending in &self.pending {
            if !protected_matches_audience(&pending.operation, audience) {
                return Err(DiagnosticBundleError::InvalidDisclosure);
            }
            if pending.operation_ordinal >= ABILITY_LIMITS_V1.max_graph_nodes as usize
                || pending.blocking_dependencies > ABILITY_LIMITS_V1.max_graph_edges as usize
            {
                return Err(DiagnosticBundleError::ItemLimit);
            }
            if previous_pending_ordinal
                .is_some_and(|previous| previous >= pending.operation_ordinal)
            {
                return Err(DiagnosticBundleError::DuplicatePendingOperation);
            }
            if let Some(nodes) = &nodes {
                let Some(PlanNodeKey::Operation { key }) = nodes.get(pending.operation_ordinal)
                else {
                    return Err(DiagnosticBundleError::UnknownOperation);
                };
                if pending.operation_ordinal >= operation_count {
                    return Err(DiagnosticBundleError::UnknownOperation);
                }
                if let ProtectedValue::Disclosed { value } = &pending.operation {
                    if value.plan != self.plan || value.operation != *key {
                        return Err(DiagnosticBundleError::UnknownOperation);
                    }
                }
            }
            previous_pending_ordinal = Some(pending.operation_ordinal);
        }

        if self
            .events
            .windows(2)
            .any(|pair| pair[0].sequence >= pair[1].sequence)
        {
            return Err(DiagnosticBundleError::NoncanonicalEventOrder);
        }
        let mut last_elapsed_by_node = BTreeMap::new();
        for event in &self.events {
            validate_event_shape(event, audience, nodes.as_deref(), plan)?;
            if let (
                Some(node_ordinal),
                TimelineTiming::OperationRecoveryElapsed { elapsed_millis },
            ) = (event.node_ordinal, event.timing)
            {
                if last_elapsed_by_node
                    .insert(node_ordinal, elapsed_millis)
                    .is_some_and(|previous| previous > elapsed_millis)
                {
                    return Err(DiagnosticBundleError::NoncanonicalElapsedTime);
                }
            }
        }
        Ok(())
    }
}

/// Owns checked offline inputs, artifact identities, and a protected timeline.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticBundle {
    schema: String,
    required_features: Vec<RequiredFeature>,
    inspection_bundle: Sha256Digest,
    plan: PlanId,
    binding_plan: PlanId,
    audience: DiagnosticBundleAudience,
    inputs: ProtectedValue<InspectionBundle>,
    artifacts: Vec<DiagnosticArtifact>,
    timeline: ExecutionTimeline,
    offline_replay: ReplayAvailability,
    limitations: Vec<DiagnosticLimitation>,
}

/// Reports why a diagnostic timeline or bundle could not be constructed.
#[derive(Debug, Error)]
pub enum DiagnosticBundleError {
    /// Bounded strict JSON decoding failed.
    #[error("diagnostic bundle decoding failed: {0}")]
    Decode(#[source] anyhow::Error),
    /// The schema discriminator is unsupported.
    #[error("diagnostic bundle has an unsupported schema discriminator")]
    UnsupportedSchema,
    /// Version 1 does not support optional feature semantics.
    #[error("diagnostic bundle requires unsupported feature semantics")]
    UnsupportedFeatures,
    /// The bytes are valid JSON but are not their canonical representation.
    #[error("diagnostic bundle is not canonically encoded")]
    NoncanonicalEncoding,
    /// A field's disclosure marker disagrees with the bundle audience.
    #[error("diagnostic bundle disclosure is inconsistent with its audience")]
    InvalidDisclosure,
    /// The bundle-authored replay availability or limitations are inconsistent.
    #[error("diagnostic bundle reports inconsistent replay limitations")]
    InvalidLimitations,
    /// A redacted export cannot supply the exact pure replay inputs.
    #[error(
        "diagnostic bundle inputs are redacted; offline replay requires an authorized deployment bundle"
    )]
    ReplayInputsRedacted,
    /// Embedded inspection inputs failed exact revalidation.
    #[error("diagnostic bundle inspection inputs failed validation: {0}")]
    InspectionBundle(#[from] InspectionBundleError),
    /// Immutable artifact identities disagree with the embedded checked plan.
    #[error("diagnostic bundle artifact identities are inconsistent")]
    ArtifactMismatch,
    /// A timeline operation belongs to another plan or is absent from plan order.
    #[error("diagnostic timeline references an unknown checked operation")]
    UnknownOperation,
    /// An event subject is absent from the checked plan.
    #[error("diagnostic timeline references an unknown checked node")]
    UnknownNode,
    /// Canonical checked node order contains a duplicate identity.
    #[error("diagnostic timeline checked node order contains a duplicate identity")]
    DuplicateNode,
    /// Pending state repeats one checked operation.
    #[error("diagnostic timeline repeats one pending operation")]
    DuplicatePendingOperation,
    /// Pending claims were supplied while the source marked them unavailable.
    #[error("diagnostic timeline pending-state availability is inconsistent")]
    InvalidPendingState,
    /// Durable events are not strictly increasing by journal sequence.
    #[error("diagnostic timeline events are not in strict journal order")]
    NoncanonicalEventOrder,
    /// Durable recovery time moves backwards for one operation.
    #[error("diagnostic timeline recovery time moves backwards for an operation")]
    NoncanonicalElapsedTime,
    /// An event subject is absent or has a node kind inconsistent with the event.
    #[error("diagnostic timeline event has an inconsistent subject")]
    InvalidEventScope,
    /// An event's attempt field disagrees with its runtime event shape.
    #[error("diagnostic timeline event has an inconsistent attempt")]
    InvalidEventAttempt,
    /// A branch event's selected alternative is absent or inconsistent.
    #[error("diagnostic timeline branch selection is inconsistent")]
    InvalidBranchSelection,
    /// An event's timing field disagrees with its runtime event shape.
    #[error("diagnostic timeline event has inconsistent recovery timing")]
    InvalidEventTiming,
    /// A timeline collection exceeds its version-1 graph bound.
    #[error("diagnostic timeline exceeds its item limit")]
    ItemLimit,
    /// Timeline and checked bundle refer to different effect plans.
    #[error("diagnostic timeline and inspection bundle identify different plans")]
    PlanMismatch,
    /// Canonical JSON encoding failed.
    #[error("diagnostic bundle encoding failed: {0}")]
    Encoding(#[source] anyhow::Error),
    /// The encoded diagnostic bundle exceeds the version-1 byte bound.
    #[error("diagnostic bundle exceeds its encoded byte limit")]
    EncodedSizeLimit,
}

impl DiagnosticBundle {
    /// Builds an export from a semantically checked inspection bundle and timeline.
    ///
    /// The audience is a caller-selected disclosure policy, not authentication.
    /// Frontends must independently authorize deployment disclosure. Redacted
    /// exports deliberately retain exact commitments and stable ordinals, which
    /// may correlate them with separately held deployment data.
    ///
    /// # Errors
    ///
    /// Returns an error if timeline and plan identities differ or canonical
    /// output exceeds its version-1 byte bound.
    pub fn from_checked(
        checked: &CheckedInspectionBundle,
        timeline: ExecutionTimeline,
    ) -> Result<Self, DiagnosticBundleError> {
        if timeline.plan() != checked.plan().id() {
            return Err(DiagnosticBundleError::PlanMismatch);
        }
        let audience = timeline.audience();
        timeline.validate(audience, Some(checked.plan()))?;
        let artifacts = diagnostic_artifacts(checked, audience);
        let redacted = audience == DiagnosticBundleAudience::Redacted;
        let inputs = if redacted {
            ProtectedValue::Redacted
        } else {
            ProtectedValue::Disclosed {
                value: checked.bundle().clone(),
            }
        };
        let offline_replay = if redacted {
            ReplayAvailability::InputsRedacted
        } else {
            ReplayAvailability::Available
        };
        let limitations =
            diagnostic_limitations(audience, timeline.provenance(), timeline.pending_state());
        let diagnostic = Self {
            schema: DIAGNOSTIC_BUNDLE_SCHEMA.to_string(),
            required_features: Vec::new(),
            inspection_bundle: checked.digest(),
            plan: checked.plan().id(),
            binding_plan: checked.plan().binding_plan().id(),
            audience,
            inputs,
            artifacts,
            timeline,
            offline_replay,
            limitations,
        };
        diagnostic.canonical_bytes()?;
        Ok(diagnostic)
    }

    /// Decodes one strictly bounded canonical diagnostic export.
    ///
    /// Deployment exports also reconstruct and validate the embedded inspection
    /// bundle. This establishes local semantic consistency only; it does not
    /// authenticate the journal provenance asserted by the export.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, noncanonical, unsupported,
    /// internally inconsistent, or semantically invalid input.
    pub fn decode(bytes: &[u8]) -> Result<Self, DiagnosticBundleError> {
        let diagnostic = diagnostic_limits()
            .decode::<Self>(bytes, DIAGNOSTIC_BUNDLE_SCHEMA)
            .map_err(DiagnosticBundleError::Decode)?;
        diagnostic.validate_complete()?;
        if diagnostic.encode_canonical()? != bytes {
            return Err(DiagnosticBundleError::NoncanonicalEncoding);
        }
        Ok(diagnostic)
    }

    /// Reconstructs the exact checked inputs carried by a deployment export.
    ///
    /// The returned value is checked against the bundle's inspection, binding,
    /// and effect-plan commitments and against its exported artifact identities
    /// and timeline membership. Caller-asserted journal provenance remains an
    /// unauthenticated claim.
    ///
    /// # Errors
    ///
    /// Returns an error when inputs are redacted or any embedded commitment,
    /// checked plan, artifact identity, timeline record, or disclosure field is
    /// inconsistent.
    pub fn replay_inputs(&self) -> Result<CheckedInspectionBundle, DiagnosticBundleError> {
        self.validate_envelope()?;
        let ProtectedValue::Disclosed { value } = &self.inputs else {
            return Err(DiagnosticBundleError::ReplayInputsRedacted);
        };
        let checked = value.clone().check(Some(self.inspection_bundle))?;
        if checked.plan().id() != self.plan
            || checked.plan().binding_plan().id() != self.binding_plan
        {
            return Err(DiagnosticBundleError::PlanMismatch);
        }

        self.timeline
            .validate(self.audience, Some(checked.plan()))?;
        if self.artifacts != diagnostic_artifacts(&checked, self.audience) {
            return Err(DiagnosticBundleError::ArtifactMismatch);
        }
        Ok(checked)
    }

    /// Returns the exact checked effect-plan identity.
    #[must_use]
    pub const fn plan(&self) -> PlanId {
        self.plan
    }

    /// Returns the exact portable inspection-bundle commitment.
    #[must_use]
    pub const fn inspection_bundle(&self) -> Sha256Digest {
        self.inspection_bundle
    }

    /// Returns the exact checked binding-plan identity.
    #[must_use]
    pub const fn binding_plan(&self) -> PlanId {
        self.binding_plan
    }

    /// Returns the caller-selected disclosure audience.
    #[must_use]
    pub const fn audience(&self) -> DiagnosticBundleAudience {
        self.audience
    }

    /// Returns the embedded pure inputs or their redaction marker.
    #[must_use]
    pub const fn inputs(&self) -> &ProtectedValue<InspectionBundle> {
        &self.inputs
    }

    /// Returns immutable artifact identities with protected store locations.
    #[must_use]
    pub fn artifacts(&self) -> &[DiagnosticArtifact] {
        &self.artifacts
    }

    /// Returns the bounded redaction-safe execution timeline.
    #[must_use]
    pub const fn timeline(&self) -> &ExecutionTimeline {
        &self.timeline
    }

    /// Reports whether this export alone contains pure replay inputs.
    #[must_use]
    pub const fn offline_replay(&self) -> ReplayAvailability {
        self.offline_replay
    }

    /// Returns explicit privacy and replay limitations.
    #[must_use]
    pub fn limitations(&self) -> &[DiagnosticLimitation] {
        &self.limitations
    }

    /// Encodes this diagnostic bundle as bounded canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical serialization fails or the document
    /// exceeds its version-1 byte bound.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DiagnosticBundleError> {
        self.validate_complete()?;
        self.encode_canonical()
    }

    fn validate_complete(&self) -> Result<(), DiagnosticBundleError> {
        self.validate_envelope()?;
        if self.audience == DiagnosticBundleAudience::Deployment {
            self.replay_inputs()?;
        }
        Ok(())
    }

    fn validate_envelope(&self) -> Result<(), DiagnosticBundleError> {
        if self.schema != DIAGNOSTIC_BUNDLE_SCHEMA {
            return Err(DiagnosticBundleError::UnsupportedSchema);
        }
        if !self.required_features.is_empty() {
            return Err(DiagnosticBundleError::UnsupportedFeatures);
        }
        if self.timeline.plan() != self.plan {
            return Err(DiagnosticBundleError::PlanMismatch);
        }
        if !protected_matches_audience(&self.inputs, self.audience)
            || self
                .artifacts
                .iter()
                .any(|artifact| !protected_matches_audience(&artifact.store_path, self.audience))
        {
            return Err(DiagnosticBundleError::InvalidDisclosure);
        }

        let expected_replay = match self.audience {
            DiagnosticBundleAudience::Deployment => ReplayAvailability::Available,
            DiagnosticBundleAudience::Redacted => ReplayAvailability::InputsRedacted,
        };
        if self.offline_replay != expected_replay
            || self.limitations
                != diagnostic_limitations(
                    self.audience,
                    self.timeline.provenance(),
                    self.timeline.pending_state(),
                )
        {
            return Err(DiagnosticBundleError::InvalidLimitations);
        }
        self.timeline.validate(self.audience, None)
    }

    fn encode_canonical(&self) -> Result<Vec<u8>, DiagnosticBundleError> {
        let mut writer = DiagnosticBoundedWriter::new(DIAGNOSTIC_BUNDLE_MAX_BYTES);
        serde_json::to_writer(&mut writer, self).map_err(|error| {
            if writer.exceeded {
                DiagnosticBundleError::EncodedSizeLimit
            } else {
                DiagnosticBundleError::Encoding(error.into())
            }
        })?;
        aos_contract::canonical::to_vec(self).map_err(DiagnosticBundleError::Encoding)
    }
}

fn node_ordinals(
    plan: &CheckedEffectPlan,
) -> Result<BTreeMap<PlanNodeKey, usize>, DiagnosticBundleError> {
    let mut ordinals = BTreeMap::new();
    for (ordinal, node) in checked_nodes(plan)?.into_iter().enumerate() {
        if ordinals.insert(node, ordinal).is_some() {
            return Err(DiagnosticBundleError::DuplicateNode);
        }
    }
    Ok(ordinals)
}

fn timeline_event(
    event: TimelineEventInput,
    plan: &CheckedEffectPlan,
    nodes: &BTreeMap<PlanNodeKey, usize>,
    audience: DiagnosticBundleAudience,
) -> Result<TimelineEvent, DiagnosticBundleError> {
    let expected_subject = event.kind.subject_kind();
    if expected_subject != event.node.as_ref().map(timeline_subject_kind) {
        return Err(DiagnosticBundleError::InvalidEventScope);
    }
    if expected_subject != Some(TimelineSubjectKind::Operation) && event.attempt.is_some() {
        return Err(DiagnosticBundleError::InvalidEventScope);
    }
    let (node_ordinal, node) = match &event.node {
        Some(node) => {
            let ordinal = nodes
                .get(node)
                .copied()
                .ok_or(DiagnosticBundleError::UnknownNode)?;
            (Some(ordinal), Some(protect(node.clone(), audience)))
        }
        None => (None, None),
    };
    let (selected_alternative_ordinal, selected_alternative) =
        match (event.kind, event.node.as_ref(), event.selected_alternative) {
            (
                TimelineEventKind::BranchSelected,
                Some(PlanNodeKey::Decision { key }),
                Some(alternative),
            ) => {
                let decision = plan
                    .document()
                    .decisions
                    .iter()
                    .find(|decision| decision.key == *key)
                    .ok_or(DiagnosticBundleError::UnknownNode)?;
                let ordinal = decision
                    .alternatives
                    .iter()
                    .position(|candidate| candidate.key == alternative)
                    .ok_or(DiagnosticBundleError::InvalidBranchSelection)?;
                (Some(ordinal), Some(protect(alternative, audience)))
            }
            (TimelineEventKind::BranchSelected, _, _) | (_, _, Some(_)) => {
                return Err(DiagnosticBundleError::InvalidBranchSelection);
            }
            (_, _, None) => (None, None),
        };
    Ok(TimelineEvent {
        sequence: event.sequence,
        kind: event.kind,
        node_ordinal,
        node,
        attempt: event.attempt,
        selected_alternative_ordinal,
        selected_alternative,
        timing: event.timing,
    })
}

fn checked_nodes(plan: &CheckedEffectPlan) -> Result<Vec<PlanNodeKey>, DiagnosticBundleError> {
    let document = plan.document();
    let nodes = document
        .operations
        .iter()
        .map(|operation| PlanNodeKey::Operation {
            key: operation.key.clone(),
        })
        .chain(
            document
                .decisions
                .iter()
                .map(|decision| PlanNodeKey::Decision {
                    key: decision.key.clone(),
                }),
        )
        .chain(document.merges.iter().map(|merge| PlanNodeKey::Merge {
            key: merge.key.clone(),
        }))
        .collect::<Vec<_>>();
    if nodes.len() > ABILITY_LIMITS_V1.max_graph_nodes as usize {
        return Err(DiagnosticBundleError::ItemLimit);
    }
    Ok(nodes)
}

fn validate_event_shape(
    event: &TimelineEvent,
    audience: DiagnosticBundleAudience,
    nodes: Option<&[PlanNodeKey]>,
    plan: Option<&CheckedEffectPlan>,
) -> Result<(), DiagnosticBundleError> {
    match event.kind.subject_kind() {
        None if event.node_ordinal.is_none() && event.node.is_none() => {}
        Some(expected_kind) => {
            let (Some(ordinal), Some(node)) = (event.node_ordinal, event.node.as_ref()) else {
                return Err(DiagnosticBundleError::InvalidEventScope);
            };
            if ordinal >= ABILITY_LIMITS_V1.max_graph_nodes as usize
                || !protected_matches_audience(node, audience)
            {
                return Err(DiagnosticBundleError::InvalidEventScope);
            }
            if let Some(nodes) = nodes {
                let expected_node = nodes
                    .get(ordinal)
                    .ok_or(DiagnosticBundleError::UnknownNode)?;
                if timeline_subject_kind(expected_node) != expected_kind {
                    return Err(DiagnosticBundleError::InvalidEventScope);
                }
                if let ProtectedValue::Disclosed { value } = node {
                    if value != expected_node {
                        return Err(DiagnosticBundleError::UnknownNode);
                    }
                }
            }
        }
        _ => return Err(DiagnosticBundleError::InvalidEventScope),
    }

    match (event.kind.attempt_requirement(), event.attempt) {
        (AttemptRequirement::Required, Some(_))
        | (AttemptRequirement::Optional, _)
        | (AttemptRequirement::Forbidden, None) => {}
        _ => return Err(DiagnosticBundleError::InvalidEventAttempt),
    }
    match (
        event.kind,
        event.selected_alternative_ordinal,
        event.selected_alternative.as_ref(),
    ) {
        (TimelineEventKind::BranchSelected, Some(ordinal), Some(alternative))
            if ordinal < ABILITY_LIMITS_V1.max_collection_items as usize
                && protected_matches_audience(alternative, audience) =>
        {
            if let Some(plan) = plan {
                let Some(node_ordinal) = event.node_ordinal else {
                    return Err(DiagnosticBundleError::InvalidBranchSelection);
                };
                let Some(nodes) = nodes else {
                    return Err(DiagnosticBundleError::InvalidBranchSelection);
                };
                let Some(PlanNodeKey::Decision { key }) = nodes.get(node_ordinal) else {
                    return Err(DiagnosticBundleError::InvalidBranchSelection);
                };
                let decision = plan
                    .document()
                    .decisions
                    .iter()
                    .find(|decision| decision.key == *key)
                    .ok_or(DiagnosticBundleError::InvalidBranchSelection)?;
                let expected = decision
                    .alternatives
                    .get(ordinal)
                    .ok_or(DiagnosticBundleError::InvalidBranchSelection)?;
                if let ProtectedValue::Disclosed { value } = alternative {
                    if value != &expected.key {
                        return Err(DiagnosticBundleError::InvalidBranchSelection);
                    }
                }
            }
        }
        (_, None, None) if event.kind != TimelineEventKind::BranchSelected => {}
        _ => return Err(DiagnosticBundleError::InvalidBranchSelection),
    }
    match (event.kind.timing_requirement(), event.timing) {
        (TimingRequirement::Unavailable, TimelineTiming::Unavailable)
        | (
            TimingRequirement::OperationRecoveryElapsed,
            TimelineTiming::OperationRecoveryElapsed { .. },
        ) => {}
        _ => return Err(DiagnosticBundleError::InvalidEventTiming),
    }
    Ok(())
}

const fn timeline_subject_kind(node: &PlanNodeKey) -> TimelineSubjectKind {
    match node {
        PlanNodeKey::Operation { .. } => TimelineSubjectKind::Operation,
        PlanNodeKey::Decision { .. } => TimelineSubjectKind::Decision,
        PlanNodeKey::Merge { .. } => TimelineSubjectKind::Merge,
    }
}

fn protect<T>(value: T, audience: DiagnosticBundleAudience) -> ProtectedValue<T> {
    match audience {
        DiagnosticBundleAudience::Deployment => ProtectedValue::Disclosed { value },
        DiagnosticBundleAudience::Redacted => ProtectedValue::Redacted,
    }
}

const fn protected_matches_audience<T>(
    value: &ProtectedValue<T>,
    audience: DiagnosticBundleAudience,
) -> bool {
    matches!(
        (value, audience),
        (
            ProtectedValue::Disclosed { .. },
            DiagnosticBundleAudience::Deployment
        ) | (ProtectedValue::Redacted, DiagnosticBundleAudience::Redacted)
    )
}

fn diagnostic_artifacts(
    checked: &CheckedInspectionBundle,
    audience: DiagnosticBundleAudience,
) -> Vec<DiagnosticArtifact> {
    checked
        .bundle()
        .effect_document()
        .artifacts
        .iter()
        .map(|artifact| DiagnosticArtifact {
            content: artifact.content,
            nar_hash: artifact.nar_hash,
            closure: artifact.closure,
            store_path: protect(artifact.store_path.clone(), audience),
        })
        .collect()
}

fn diagnostic_limitations(
    audience: DiagnosticBundleAudience,
    provenance: TimelineProvenance,
    pending_state: PendingStateAvailability,
) -> Vec<DiagnosticLimitation> {
    let mut limitations = Vec::new();
    if audience == DiagnosticBundleAudience::Redacted {
        limitations.extend([
            DiagnosticLimitation::CommitmentCorrelationRetained,
            DiagnosticLimitation::NormalizedInputsRedacted,
            DiagnosticLimitation::ExecutionTopologyRedacted,
            DiagnosticLimitation::ArtifactLocationsRedacted,
        ]);
    }
    limitations.push(DiagnosticLimitation::ExecutionEvidenceRedacted);
    limitations.push(DiagnosticLimitation::NativeExecutionQualificationNotIncluded);
    if pending_state == PendingStateAvailability::Unavailable {
        limitations.push(DiagnosticLimitation::PendingDependencyStateUnavailable);
    }
    if provenance == TimelineProvenance::UnverifiedRetainedRecords {
        limitations.push(DiagnosticLimitation::ExecutionRecordProvenanceUnverified);
    }
    limitations.extend([
        DiagnosticLimitation::JournalAuthenticationNotVerified,
        DiagnosticLimitation::RetainedRecordsNotLiveObservation,
    ]);
    if matches!(
        provenance,
        TimelineProvenance::CallerAssertedJournalPrefix { .. }
    ) {
        limitations.push(DiagnosticLimitation::IncompleteJournalTailExcluded);
    }
    if audience == DiagnosticBundleAudience::Redacted {
        limitations.push(DiagnosticLimitation::OfflineReplayInputsRedacted);
    }
    limitations
}

fn diagnostic_limits() -> JsonLimits {
    JsonLimits {
        max_bytes: DIAGNOSTIC_BUNDLE_MAX_BYTES,
        max_depth: (ABILITY_LIMITS_V1.max_structural_depth as usize).saturating_add(4),
        max_items: (ABILITY_LIMITS_V1.max_collection_items as usize)
            .saturating_mul(DIAGNOSTIC_BUNDLE_COMPONENT_LIMIT),
        max_string_bytes: ABILITY_LIMITS_V1.max_string_bytes as usize,
    }
}

struct DiagnosticBoundedWriter {
    remaining: usize,
    exceeded: bool,
}

impl DiagnosticBoundedWriter {
    const fn new(limit: usize) -> Self {
        Self {
            remaining: limit,
            exceeded: false,
        }
    }
}

impl Write for DiagnosticBoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other(
                "serialized diagnostic bundle exceeds its byte limit",
            ));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use aos_ability_model::{
        DecisionAlternative, DecisionNode, DecisionPredicate, DecisionSelector, DependencyEdge,
        DependencyKind, LocalKey, OperationResultReference, ResultProducerKey, ScopePath,
        ScopedOperationKey, TransactionId,
    };
    use aos_ability_validate::test_support::{
        checked_effect_plan, checked_systemd_manager_effect_plan, plan_fixture,
    };

    use super::*;

    #[test]
    fn redacted_bundle_keeps_timeline_and_artifact_identity_without_private_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = checked_effect_plan();
        let bundle = InspectionBundle::from_checked(&plan)?;
        let bundle_digest = bundle.digest()?;
        let checked = bundle.check(Some(bundle_digest))?;
        let operation = OperationId {
            plan: plan.id(),
            operation: plan.document().operations[0].key.clone(),
        };
        let operation_node = PlanNodeKey::Operation {
            key: operation.operation.clone(),
        };
        let timeline = ExecutionTimeline::from_records(
            TransactionId(LocalKey::new("private-transaction")?),
            &plan,
            PendingStateAvailability::RetainedClaims,
            vec![PendingOperationInput {
                operation: operation.clone(),
                blocking_dependencies: 1,
            }],
            vec![
                TimelineEventInput {
                    sequence: 1,
                    kind: TimelineEventKind::TransactionPlanned,
                    node: None,
                    attempt: None,
                    selected_alternative: None,
                    timing: TimelineTiming::Unavailable,
                },
                TimelineEventInput {
                    sequence: 2,
                    kind: TimelineEventKind::OperationAdmitted,
                    node: Some(operation_node),
                    attempt: NonZeroU32::new(1),
                    selected_alternative: None,
                    timing: TimelineTiming::OperationRecoveryElapsed { elapsed_millis: 5 },
                },
            ],
            TimelineProvenance::UnverifiedRetainedRecords,
            DiagnosticBundleAudience::Redacted,
        )?;
        let diagnostic = DiagnosticBundle::from_checked(&checked, timeline)?;

        assert_eq!(
            diagnostic.offline_replay(),
            ReplayAvailability::InputsRedacted
        );
        assert!(matches!(diagnostic.inputs(), ProtectedValue::Redacted));
        assert_eq!(diagnostic.timeline().events()[1].node_ordinal(), Some(0));
        assert_eq!(diagnostic.timeline().events().len(), 2);
        assert!(matches!(
            diagnostic.timeline().events()[1].node(),
            Some(ProtectedValue::Redacted)
        ));
        assert!(
            diagnostic
                .artifacts()
                .iter()
                .all(|artifact| matches!(artifact.store_path, ProtectedValue::Redacted))
        );
        assert_eq!(
            diagnostic.limitations(),
            &[
                DiagnosticLimitation::CommitmentCorrelationRetained,
                DiagnosticLimitation::NormalizedInputsRedacted,
                DiagnosticLimitation::ExecutionTopologyRedacted,
                DiagnosticLimitation::ArtifactLocationsRedacted,
                DiagnosticLimitation::ExecutionEvidenceRedacted,
                DiagnosticLimitation::NativeExecutionQualificationNotIncluded,
                DiagnosticLimitation::ExecutionRecordProvenanceUnverified,
                DiagnosticLimitation::JournalAuthenticationNotVerified,
                DiagnosticLimitation::RetainedRecordsNotLiveObservation,
                DiagnosticLimitation::OfflineReplayInputsRedacted,
            ]
        );

        let bytes = diagnostic.canonical_bytes()?;
        for private_value in ["private-transaction", "\"observe\"", "/nix/store/"] {
            assert!(
                !bytes
                    .windows(private_value.len())
                    .any(|window| window == private_value.as_bytes())
            );
        }
        Ok(())
    }

    #[test]
    fn deployment_bundle_retains_inputs_but_never_runtime_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = checked_effect_plan();
        let bundle = InspectionBundle::from_checked(&plan)?;
        let bundle_digest = bundle.digest()?;
        let checked = bundle.check(Some(bundle_digest))?;
        let operation = OperationId {
            plan: plan.id(),
            operation: plan.document().operations[0].key.clone(),
        };
        let operation_node = PlanNodeKey::Operation {
            key: operation.operation.clone(),
        };
        let timeline = ExecutionTimeline::from_records(
            TransactionId(LocalKey::new("transaction")?),
            &plan,
            PendingStateAvailability::Unavailable,
            Vec::new(),
            vec![TimelineEventInput {
                sequence: 1,
                kind: TimelineEventKind::EffectCompleted,
                node: Some(operation_node),
                attempt: NonZeroU32::new(1),
                selected_alternative: None,
                timing: TimelineTiming::OperationRecoveryElapsed { elapsed_millis: 8 },
            }],
            TimelineProvenance::CallerAssertedJournalAnchor {
                journal: Sha256Digest::of_bytes("journal"),
            },
            DiagnosticBundleAudience::Deployment,
        )?;
        let diagnostic = DiagnosticBundle::from_checked(&checked, timeline)?;

        assert_eq!(diagnostic.offline_replay(), ReplayAvailability::Available);
        assert!(matches!(
            diagnostic.inputs(),
            ProtectedValue::Disclosed { .. }
        ));
        assert_eq!(
            diagnostic.limitations(),
            &[
                DiagnosticLimitation::ExecutionEvidenceRedacted,
                DiagnosticLimitation::NativeExecutionQualificationNotIncluded,
                DiagnosticLimitation::PendingDependencyStateUnavailable,
                DiagnosticLimitation::JournalAuthenticationNotVerified,
                DiagnosticLimitation::RetainedRecordsNotLiveObservation,
            ]
        );
        Ok(())
    }

    #[test]
    fn timeline_rejects_foreign_operations_scope_errors_and_reordered_events()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = checked_effect_plan();
        let operation = OperationId {
            plan: plan.id(),
            operation: plan.document().operations[0].key.clone(),
        };
        let operation_node = PlanNodeKey::Operation {
            key: operation.operation.clone(),
        };
        let transaction = TransactionId(LocalKey::new("transaction")?);

        let foreign_pending = ExecutionTimeline::from_records(
            transaction.clone(),
            &plan,
            PendingStateAvailability::RetainedClaims,
            vec![PendingOperationInput {
                operation: OperationId {
                    plan: PlanId(Sha256Digest::of_bytes("foreign-plan")),
                    operation: operation.operation.clone(),
                },
                blocking_dependencies: 1,
            }],
            Vec::new(),
            TimelineProvenance::UnverifiedRetainedRecords,
            DiagnosticBundleAudience::Redacted,
        );
        assert!(matches!(
            foreign_pending,
            Err(DiagnosticBundleError::UnknownOperation)
        ));

        let reordered = ExecutionTimeline::from_records(
            transaction.clone(),
            &plan,
            PendingStateAvailability::Unavailable,
            Vec::new(),
            vec![
                TimelineEventInput {
                    sequence: 2,
                    kind: TimelineEventKind::TransactionPlanned,
                    node: None,
                    attempt: None,
                    selected_alternative: None,
                    timing: TimelineTiming::Unavailable,
                },
                TimelineEventInput {
                    sequence: 1,
                    kind: TimelineEventKind::EffectStarted,
                    node: Some(operation_node),
                    attempt: NonZeroU32::new(1),
                    selected_alternative: None,
                    timing: TimelineTiming::Unavailable,
                },
            ],
            TimelineProvenance::UnverifiedRetainedRecords,
            DiagnosticBundleAudience::Redacted,
        );
        assert!(matches!(
            reordered,
            Err(DiagnosticBundleError::NoncanonicalEventOrder)
        ));

        let invalid_scope = ExecutionTimeline::from_records(
            transaction,
            &plan,
            PendingStateAvailability::Unavailable,
            Vec::new(),
            vec![TimelineEventInput {
                sequence: 1,
                kind: TimelineEventKind::EffectStarted,
                node: None,
                attempt: NonZeroU32::new(1),
                selected_alternative: None,
                timing: TimelineTiming::Unavailable,
            }],
            TimelineProvenance::UnverifiedRetainedRecords,
            DiagnosticBundleAudience::Redacted,
        );
        assert!(matches!(
            invalid_scope,
            Err(DiagnosticBundleError::InvalidEventScope)
        ));
        Ok(())
    }

    #[test]
    fn timeline_enforces_event_timing_shape_and_rejects_operation_recovery_regression()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = checked_effect_plan();
        let operation_node = PlanNodeKey::Operation {
            key: plan.document().operations[0].key.clone(),
        };
        let transaction = TransactionId(LocalKey::new("transaction")?);
        let event = |sequence, kind, timing| TimelineEventInput {
            sequence,
            kind,
            node: Some(operation_node.clone()),
            attempt: NonZeroU32::new(1),
            selected_alternative: None,
            timing,
        };

        let missing_operation_timing = ExecutionTimeline::from_records(
            transaction.clone(),
            &plan,
            PendingStateAvailability::Unavailable,
            Vec::new(),
            vec![event(
                1,
                TimelineEventKind::EffectStarted,
                TimelineTiming::Unavailable,
            )],
            TimelineProvenance::UnverifiedRetainedRecords,
            DiagnosticBundleAudience::Redacted,
        );
        assert!(matches!(
            missing_operation_timing,
            Err(DiagnosticBundleError::InvalidEventTiming)
        ));

        let backwards = ExecutionTimeline::from_records(
            transaction,
            &plan,
            PendingStateAvailability::Unavailable,
            Vec::new(),
            vec![
                event(
                    1,
                    TimelineEventKind::OperationAdmitted,
                    TimelineTiming::OperationRecoveryElapsed { elapsed_millis: 9 },
                ),
                event(
                    2,
                    TimelineEventKind::EffectStarted,
                    TimelineTiming::OperationRecoveryElapsed { elapsed_millis: 1 },
                ),
            ],
            TimelineProvenance::UnverifiedRetainedRecords,
            DiagnosticBundleAudience::Redacted,
        );
        assert!(matches!(
            backwards,
            Err(DiagnosticBundleError::NoncanonicalElapsedTime)
        ));
        Ok(())
    }

    #[test]
    fn timeline_tracks_recovery_elapsed_per_operation_across_interleaved_retries()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = plan_fixture();
        let mut second_operation = fixture.effect_plan.operations[0].clone();
        second_operation.key.key = LocalKey::new("observe-second")?;
        fixture.effect_plan.operations.push(second_operation);
        let plan = fixture.validate()?;
        let first = PlanNodeKey::Operation {
            key: plan.document().operations[0].key.clone(),
        };
        let second = PlanNodeKey::Operation {
            key: plan.document().operations[1].key.clone(),
        };
        let event = |sequence, node, elapsed_millis| TimelineEventInput {
            sequence,
            kind: TimelineEventKind::RetryScheduled,
            node: Some(node),
            attempt: NonZeroU32::new(1),
            selected_alternative: None,
            timing: TimelineTiming::OperationRecoveryElapsed { elapsed_millis },
        };

        let timeline = ExecutionTimeline::from_records(
            TransactionId(LocalKey::new("transaction")?),
            &plan,
            PendingStateAvailability::Unavailable,
            Vec::new(),
            vec![
                event(1, first.clone(), 9),
                event(2, second, 1),
                event(3, first, 10),
            ],
            TimelineProvenance::UnverifiedRetainedRecords,
            DiagnosticBundleAudience::Redacted,
        )?;

        assert_eq!(timeline.events().len(), 3);
        assert_eq!(timeline.events()[0].node_ordinal(), Some(0));
        assert_eq!(timeline.events()[1].node_ordinal(), Some(1));
        Ok(())
    }

    #[test]
    fn branch_selection_retains_a_checked_ordinal_and_protects_its_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = checked_branch_plan()?;
        let decision = &plan.document().decisions[0];
        let transaction = TransactionId(LocalKey::new("transaction")?);
        let event = |selected_alternative, audience| {
            ExecutionTimeline::from_records(
                transaction.clone(),
                &plan,
                PendingStateAvailability::Unavailable,
                Vec::new(),
                vec![TimelineEventInput {
                    sequence: 1,
                    kind: TimelineEventKind::BranchSelected,
                    node: Some(PlanNodeKey::Decision {
                        key: decision.key.clone(),
                    }),
                    attempt: None,
                    selected_alternative: Some(selected_alternative),
                    timing: TimelineTiming::Unavailable,
                }],
                TimelineProvenance::UnverifiedRetainedRecords,
                audience,
            )
        };

        let redacted = event(
            decision.alternatives[1].key.clone(),
            DiagnosticBundleAudience::Redacted,
        )?;
        assert_eq!(redacted.events()[0].selected_alternative_ordinal(), Some(1));
        assert!(matches!(
            redacted.events()[0].selected_alternative(),
            Some(ProtectedValue::Redacted)
        ));

        let unknown = event(
            LocalKey::new("unknown-alternative")?,
            DiagnosticBundleAudience::Deployment,
        );
        assert!(matches!(
            unknown,
            Err(DiagnosticBundleError::InvalidBranchSelection)
        ));
        Ok(())
    }

    #[test]
    fn deployment_bundle_round_trips_and_reconstructs_checked_replay_inputs()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = checked_effect_plan();
        let bundle = InspectionBundle::from_checked(&plan)?;
        let checked = bundle.clone().check(Some(bundle.digest()?))?;
        let timeline = ExecutionTimeline::from_records(
            TransactionId(LocalKey::new("transaction")?),
            &plan,
            PendingStateAvailability::Unavailable,
            Vec::new(),
            Vec::new(),
            TimelineProvenance::UnverifiedRetainedRecords,
            DiagnosticBundleAudience::Deployment,
        )?;
        let diagnostic = DiagnosticBundle::from_checked(&checked, timeline)?;

        let bytes = diagnostic.canonical_bytes()?;
        let decoded = DiagnosticBundle::decode(&bytes)?;
        let replay = decoded.replay_inputs()?;

        assert_eq!(decoded, diagnostic);
        assert_eq!(replay.digest(), checked.digest());
        assert_eq!(replay.plan().id(), checked.plan().id());
        Ok(())
    }

    #[test]
    fn redacted_bundle_decodes_but_reports_that_replay_inputs_are_unavailable()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = checked_effect_plan();
        let bundle = InspectionBundle::from_checked(&plan)?;
        let checked = bundle.clone().check(Some(bundle.digest()?))?;
        let timeline = ExecutionTimeline::from_records(
            TransactionId(LocalKey::new("transaction")?),
            &plan,
            PendingStateAvailability::Unavailable,
            Vec::new(),
            Vec::new(),
            TimelineProvenance::UnverifiedRetainedRecords,
            DiagnosticBundleAudience::Redacted,
        )?;
        let bytes = DiagnosticBundle::from_checked(&checked, timeline)?.canonical_bytes()?;

        let decoded = DiagnosticBundle::decode(&bytes)?;
        assert!(matches!(
            decoded.replay_inputs(),
            Err(DiagnosticBundleError::ReplayInputsRedacted)
        ));
        Ok(())
    }

    #[test]
    fn diagnostic_decode_rejects_noncanonical_json() -> Result<(), Box<dyn std::error::Error>> {
        let plan = checked_effect_plan();
        let bundle = InspectionBundle::from_checked(&plan)?;
        let checked = bundle.clone().check(Some(bundle.digest()?))?;
        let timeline = ExecutionTimeline::from_records(
            TransactionId(LocalKey::new("transaction")?),
            &plan,
            PendingStateAvailability::Unavailable,
            Vec::new(),
            Vec::new(),
            TimelineProvenance::UnverifiedRetainedRecords,
            DiagnosticBundleAudience::Redacted,
        )?;
        let mut bytes = DiagnosticBundle::from_checked(&checked, timeline)?.canonical_bytes()?;
        bytes.push(b'\n');

        assert!(matches!(
            DiagnosticBundle::decode(&bytes),
            Err(DiagnosticBundleError::NoncanonicalEncoding)
        ));
        Ok(())
    }

    #[test]
    fn bundle_rejects_a_timeline_from_another_checked_plan()
    -> Result<(), Box<dyn std::error::Error>> {
        let timeline_plan = checked_effect_plan();
        let timeline = ExecutionTimeline::from_records(
            TransactionId(LocalKey::new("transaction")?),
            &timeline_plan,
            PendingStateAvailability::Unavailable,
            Vec::new(),
            Vec::new(),
            TimelineProvenance::UnverifiedRetainedRecords,
            DiagnosticBundleAudience::Redacted,
        )?;
        let other_plan = checked_systemd_manager_effect_plan();
        let other_bundle = InspectionBundle::from_checked(&other_plan)?;
        let other_checked = other_bundle.check(None)?;

        assert!(matches!(
            DiagnosticBundle::from_checked(&other_checked, timeline),
            Err(DiagnosticBundleError::PlanMismatch)
        ));
        Ok(())
    }

    fn checked_branch_plan() -> Result<CheckedEffectPlan, Box<dyn std::error::Error>> {
        let mut fixture = plan_fixture();
        let operation = fixture.effect_plan.operations[0].key.clone();
        let decision = ScopedOperationKey {
            scope: ScopePath::root(),
            key: LocalKey::new("select-ready")?,
        };
        fixture.effect_plan.decisions = vec![DecisionNode {
            key: decision.clone(),
            branch_context: Vec::new(),
            selector: DecisionSelector {
                result: OperationResultReference {
                    producer: ResultProducerKey::Operation {
                        key: operation.clone(),
                    },
                    output: LocalKey::new("ready")?,
                },
                tag_field: None,
            },
            alternatives: vec![
                DecisionAlternative {
                    key: LocalKey::new("false")?,
                    predicate: DecisionPredicate::Boolean { value: false },
                },
                DecisionAlternative {
                    key: LocalKey::new("true")?,
                    predicate: DecisionPredicate::Boolean { value: true },
                },
            ],
        }];
        fixture.effect_plan.edges = vec![DependencyEdge {
            from: PlanNodeKey::Operation { key: operation },
            to: PlanNodeKey::Decision { key: decision },
            kind: DependencyKind::Data,
        }];
        Ok(fixture.validate()?)
    }
}
