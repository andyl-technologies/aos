//! Lifecycle commands and immutable causal campaign facts.
//!
//! Savepoint capture facts use these closed canonical layouts:
//!
//! ```text
//! v11 = 11:u32be | 18:u8 | command | expected-snapshot | attempt |
//!       configuration-artifact | semantic-configuration | stop | reason
//! v12 = 12:u32be | 19:u8 | command | expected-snapshot | request-fact | outcome
//! v13 = 13:u32be | 20:u8 | command | expected-snapshot | request-fact |
//!       ready-resolution-fact | continuation-attempt
//! ```

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::{
    AttemptAdmissionId, AttemptId, BranchAcceptanceSummary, BranchPointId, BranchRequestId,
    CampaignCodecError, CampaignCommandId, CampaignFactId, CampaignHash, CampaignPolicyId,
    CampaignSnapshotId, ChoiceOpportunityId, ConfigurationArtifactId, ConfigurationId, FindingId,
    ObjectiveEvaluationId, ObservationId, PlannerStepId, ProposalId, StopCondition,
};

use super::AdmissionOrdinal;

const LEGACY_CAMPAIGN_FACT_SCHEMA_VERSION: u32 = 2;
const DERIVATION_CAMPAIGN_FACT_SCHEMA_VERSION: u32 = 3;
const CREDITED_OBSERVATION_CAMPAIGN_FACT_SCHEMA_VERSION: u32 = 4;
const PIN_COMMAND_CAMPAIGN_FACT_SCHEMA_VERSION: u32 = 5;
const CAMPAIGN_FACT_SCHEMA_VERSION: u32 = 6;
const BRANCH_ACCEPTANCE_CAMPAIGN_FACT_SCHEMA_VERSION: u32 = 7;
const DISCOVERY_REQUEST_CAMPAIGN_FACT_SCHEMA_VERSION: u32 = 8;
const EXTENDED_STOP_DISCOVERY_REQUEST_CAMPAIGN_FACT_SCHEMA_VERSION: u32 = 9;
const TERMINAL_WORKER_FAILURE_CAMPAIGN_FACT_SCHEMA_VERSION: u32 = 10;
const SAVEPOINT_CAPTURE_CAMPAIGN_FACT_SCHEMA_VERSION: u32 = 11;
const SAVEPOINT_CAPTURE_RESOLUTION_CAMPAIGN_FACT_SCHEMA_VERSION: u32 = 12;
const SAVEPOINT_CONTINUATION_SELECTION_CAMPAIGN_FACT_SCHEMA_VERSION: u32 = 13;

#[derive(Clone, Copy)]
enum CampaignFactDecodeExtension {
    None,
    Derivation,
    CreditedObservation,
    PinCommand,
    ObjectiveEvaluation,
    BranchAcceptance,
    DiscoveryRequest,
    TerminalWorkerFailure,
    SavepointCapture,
    SavepointCaptureResolution,
    SavepointContinuationSelection,
    All,
}

/// Durable user intent projected from campaign accounting facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CampaignState {
    /// Created but not yet attached to execution resources.
    Created,
    /// Issuing and executing work under budget.
    Running,
    /// New work is stopped while state remains resumable.
    Paused,
    /// Current budget or finite work has completed.
    Completed,
    /// Future budget and policy mutation requires explicit unsealing.
    Sealed,
}

impl Canonical for CampaignState {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::Created => 0,
            Self::Running => 1,
            Self::Paused => 2,
            Self::Completed => 3,
            Self::Sealed => 4,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Created),
            1 => Ok(Self::Running),
            2 => Ok(Self::Paused),
            3 => Ok(Self::Completed),
            4 => Ok(Self::Sealed),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "campaign-state",
                tag,
            }),
        }
    }
}

/// Policy applied to active executions when a campaign pauses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ActiveAttemptPolicy {
    /// Allow active attempts to finish normally.
    Drain,
    /// Capture exact resumable state before releasing resources.
    ExactCheckpoint,
    /// Cancel operational work and make semantic attempts claimable again.
    CancelAndRetry,
}

impl Canonical for ActiveAttemptPolicy {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::Drain => 0,
            Self::ExactCheckpoint => 1,
            Self::CancelAndRetry => 2,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Drain),
            1 => Ok(Self::ExactCheckpoint),
            2 => Ok(Self::CancelAndRetry),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "active-attempt-policy",
                tag,
            }),
        }
    }
}

/// Idempotent semantic mutation requested of the campaign coordinator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CampaignControlAction {
    /// Begin or continue issuing work.
    Resume,
    /// Stop issuing work under the declared active-attempt policy.
    Pause(ActiveAttemptPolicy),
    /// Mark the current finite/budgeted run complete without sealing it.
    Complete,
    /// Prevent accidental budget or policy mutation.
    Seal,
    /// Re-enable explicit future mutation.
    Unseal,
    /// Activate a new immutable future policy revision.
    ActivatePolicy(CampaignPolicyId),
    /// Grant additional attempt and proposal budget.
    GrantBudget(BudgetGrant),
}

impl Canonical for CampaignControlAction {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Resume => encoder.u8(0),
            Self::Pause(policy) => {
                encoder.u8(1);
                policy.encode(encoder);
            }
            Self::Complete => encoder.u8(2),
            Self::Seal => encoder.u8(3),
            Self::Unseal => encoder.u8(4),
            Self::ActivatePolicy(policy) => {
                encoder.u8(5);
                policy.encode(encoder);
            }
            Self::GrantBudget(grant) => {
                encoder.u8(6);
                grant.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Resume),
            1 => ActiveAttemptPolicy::decode(decoder).map(Self::Pause),
            2 => Ok(Self::Complete),
            3 => Ok(Self::Seal),
            4 => Ok(Self::Unseal),
            5 => CampaignPolicyId::decode(decoder).map(Self::ActivatePolicy),
            6 => BudgetGrant::decode(decoder).map(Self::GrantBudget),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "campaign-control-action",
                tag,
            }),
        }
    }
}

/// Immutable additive campaign planning and execution budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BudgetGrant {
    /// Additional proposals permitted.
    proposals: u64,
    /// Additional new semantic attempts permitted.
    attempts: u64,
}

impl BudgetGrant {
    /// Builds a nonempty additive budget grant.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if both dimensions are zero.
    pub fn new(proposals: u64, attempts: u64) -> Result<Self, CampaignCodecError> {
        let grant = Self {
            proposals,
            attempts,
        };
        grant.validate()?;
        Ok(grant)
    }

    /// Returns the additional proposal allowance.
    #[must_use]
    pub const fn proposals(self) -> u64 {
        self.proposals
    }

    /// Returns the additional semantic-attempt allowance.
    #[must_use]
    pub const fn attempts(self) -> u64 {
        self.attempts
    }

    fn validate(self) -> Result<(), CampaignCodecError> {
        if self.proposals == 0 && self.attempts == 0 {
            Err(CampaignCodecError::InvalidValue {
                reason: "budget grant is empty",
            })
        } else {
            Ok(())
        }
    }
}

impl Canonical for BudgetGrant {
    fn encode(&self, encoder: &mut Encoder) {
        self.proposals.encode(encoder);
        self.attempts.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(u64::decode(decoder)?, u64::decode(decoder)?)
    }
}

/// Idempotent command envelope carrying an expected snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlRequest {
    /// Stable caller-supplied command identity.
    pub command: CampaignCommandId,
    /// Snapshot the caller expects to mutate.
    pub expected_snapshot: CampaignSnapshotId,
    /// Requested semantic action.
    pub action: CampaignControlAction,
}

impl ControlRequest {
    /// Returns a digest used to detect command-ID reuse with another payload.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        CampaignHash::derive("crucible.campaign-control-request.v1", &codec::encode(self))
    }
}

impl Canonical for ControlRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.command.encode(encoder);
        self.expected_snapshot.encode(encoder);
        self.action.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            command: CampaignCommandId::decode(decoder)?,
            expected_snapshot: CampaignSnapshotId::decode(decoder)?,
            action: CampaignControlAction::decode(decoder)?,
        })
    }
}

/// Immutable record that a new policy became active for future planning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PolicyActivation {
    prior: CampaignPolicyId,
    next: CampaignPolicyId,
}

/// Immutable basis of one newly derived campaign ref.
///
/// A derivation starts a new linear writer history from an authenticated source
/// snapshot. It can retain the source policy, select another compatible
/// already-imported revision, or explicitly migrate between strict and
/// streaming modes without mutating the source ref.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CampaignDerivation {
    source: CampaignSnapshotId,
    active_policy: CampaignPolicyId,
}

impl CampaignDerivation {
    /// Builds one exact semantic derivation basis.
    #[must_use]
    pub const fn new(source: CampaignSnapshotId, active_policy: CampaignPolicyId) -> Self {
        Self {
            source,
            active_policy,
        }
    }

    /// Returns the authenticated source snapshot.
    #[must_use]
    pub const fn source(self) -> CampaignSnapshotId {
        self.source
    }

    /// Returns the policy active at the derived campaign's first snapshot.
    #[must_use]
    pub const fn active_policy(self) -> CampaignPolicyId {
        self.active_policy
    }

    /// Returns the domain-separated exact semantic basis digest.
    #[must_use]
    pub fn basis_digest(self) -> CampaignHash {
        CampaignHash::derive("crucible.campaign-derivation.v1", &codec::encode(&self))
    }
}

impl Canonical for CampaignDerivation {
    fn encode(&self, encoder: &mut Encoder) {
        self.source.encode(encoder);
        self.active_policy.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self::new(
            CampaignSnapshotId::decode(decoder)?,
            CampaignPolicyId::decode(decoder)?,
        ))
    }
}

impl PolicyActivation {
    /// Builds a policy transition between distinct revisions.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when both identities are equal.
    pub fn new(
        prior: CampaignPolicyId,
        next: CampaignPolicyId,
    ) -> Result<Self, CampaignCodecError> {
        if prior == next {
            return Err(CampaignCodecError::InvalidValue {
                reason: "policy activation does not change the active policy",
            });
        }
        Ok(Self { prior, next })
    }

    /// Returns the policy active before this transition.
    #[must_use]
    pub const fn prior(self) -> CampaignPolicyId {
        self.prior
    }

    /// Returns the policy active after this transition.
    #[must_use]
    pub const fn next(self) -> CampaignPolicyId {
        self.next
    }
}

impl Canonical for PolicyActivation {
    fn encode(&self, encoder: &mut Encoder) {
        self.prior.encode(encoder);
        self.next.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            CampaignPolicyId::decode(decoder)?,
            CampaignPolicyId::decode(decoder)?,
        )
    }
}

/// Semantic pin tier independent of its current physical placement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PinRetention {
    /// Preserve semantic replay inputs only.
    Thin,
    /// Preserve the complete portable exact closure.
    Exact,
}

impl Canonical for PinRetention {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::Thin => 0,
            Self::Exact => 1,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Thin),
            1 => Ok(Self::Exact),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "pin-retention",
                tag,
            }),
        }
    }
}

/// Immutable addition or removal of one semantic configuration pin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinChange {
    /// Configuration affected by the change.
    configuration: ConfigurationId,
    /// New tier, or `None` to remove the pin.
    retention: Option<PinRetention>,
    /// Bounded operator-facing reason included in campaign history.
    reason: String,
}

impl PinChange {
    /// Builds a validated semantic pin change.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an invalid stop condition or an
    /// oversized, NUL-containing, or non-normalized reason.
    pub fn new(
        configuration: ConfigurationId,
        retention: Option<PinRetention>,
        reason: impl Into<String>,
    ) -> Result<Self, CampaignCodecError> {
        let reason = reason.into();
        codec::validate_nfc(&reason)?;
        if reason.len() > 4096 || reason.contains('\0') {
            return Err(CampaignCodecError::InvalidValue {
                reason: "pin reason is invalid",
            });
        }
        Ok(Self {
            configuration,
            retention,
            reason,
        })
    }

    /// Returns the configuration affected by this change.
    #[must_use]
    pub const fn configuration(&self) -> ConfigurationId {
        self.configuration
    }

    /// Returns the new retention tier, or `None` for removal.
    #[must_use]
    pub const fn retention(&self) -> Option<PinRetention> {
        self.retention
    }

    /// Returns the bounded operator-facing reason.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl Canonical for PinChange {
    fn encode(&self, encoder: &mut Encoder) {
        self.configuration.encode(encoder);
        self.retention.encode(encoder);
        self.reason.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            ConfigurationId::decode(decoder)?,
            Option::decode(decoder)?,
            decoder.string_bounded(4096, "pin-reason-bytes")?,
        )
    }
}

/// Idempotent semantic pin mutation carrying an exact snapshot precondition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinRequest {
    /// Stable caller-supplied command identity.
    pub command: CampaignCommandId,
    /// Snapshot the caller expects to mutate.
    pub expected_snapshot: CampaignSnapshotId,
    /// Requested semantic retention change.
    pub change: PinChange,
}

impl PinRequest {
    /// Returns a domain-separated digest of the exact command payload.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        CampaignHash::derive("crucible.campaign-pin-request.v1", &codec::encode(self))
    }
}

impl Canonical for PinRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.command.encode(encoder);
        self.expected_snapshot.encode(encoder);
        self.change.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            command: CampaignCommandId::decode(decoder)?,
            expected_snapshot: CampaignSnapshotId::decode(decoder)?,
            change: PinChange::decode(decoder)?,
        })
    }
}

/// Idempotent request for one explicit discovery attempt.
///
/// The request names the exact configuration artifact and stop semantics so
/// cold validation can reconstruct the admitted attempt without consulting
/// operational state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryRequest {
    /// Stable caller-supplied command identity.
    pub command: CampaignCommandId,
    /// Snapshot the caller expects to mutate.
    pub expected_snapshot: CampaignSnapshotId,
    /// Exact campaign-owned configuration artifact to execute.
    pub configuration: ConfigurationArtifactId,
    /// Requested semantic execution boundary.
    pub stop: StopCondition,
}

/// Durable request to capture one immutable attempt at its declared stop.
///
/// The configuration artifact is redundant with the immutable attempt on
/// purpose. Cold validation authenticates the pair before the request becomes
/// an operational capture intent. It does not admit or index the described
/// attempt as semantic campaign work. The capture request fact, rather than
/// the semantic configuration alone, identifies its retained physical source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavepointCaptureRequest {
    /// Stable caller-supplied command identity.
    pub command: CampaignCommandId,
    /// Snapshot the caller expects to mutate.
    pub expected_snapshot: CampaignSnapshotId,
    /// Immutable attempt whose reached stop boundary is captured.
    pub attempt: AttemptId,
    /// Exact configuration artifact the worker must materialize and authenticate.
    pub configuration: ConfigurationArtifactId,
    /// Semantic identity of the exact starting configuration artifact.
    pub semantic_configuration: ConfigurationId,
    /// Semantic execution boundary bound into the immutable attempt.
    pub stop: StopCondition,
    /// Bounded operator-facing reason included in campaign history.
    pub reason: String,
}

impl SavepointCaptureRequest {
    /// Builds a validated attempt-stop capture request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an invalid stop condition or an
    /// oversized, NUL-containing, or non-normalized reason.
    pub fn new(
        command: CampaignCommandId,
        expected_snapshot: CampaignSnapshotId,
        attempt: AttemptId,
        configuration: ConfigurationArtifactId,
        semantic_configuration: ConfigurationId,
        stop: StopCondition,
        reason: impl Into<String>,
    ) -> Result<Self, CampaignCodecError> {
        let reason = reason.into();
        let request = Self {
            command,
            expected_snapshot,
            attempt,
            configuration,
            semantic_configuration,
            stop,
            reason,
        };
        request.validate()?;
        Ok(request)
    }

    /// Revalidates mutable public fields before repository publication.
    pub(crate) fn validate(&self) -> Result<(), CampaignCodecError> {
        self.stop.validate()?;
        codec::validate_nfc(&self.reason)?;
        if self.reason.len() > 4096 || self.reason.contains('\0') {
            return Err(CampaignCodecError::InvalidValue {
                reason: "savepoint capture reason is invalid",
            });
        }
        Ok(())
    }

    /// Returns a domain-separated digest of the exact command payload.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        CampaignHash::derive(
            "crucible.campaign-savepoint-capture-request.v1",
            &codec::encode(self),
        )
    }
}

impl Canonical for SavepointCaptureRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.command.encode(encoder);
        self.expected_snapshot.encode(encoder);
        self.attempt.encode(encoder);
        self.configuration.encode(encoder);
        self.semantic_configuration.encode(encoder);
        self.stop.encode(encoder);
        self.reason.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let command = CampaignCommandId::decode(decoder)?;
        let expected_snapshot = CampaignSnapshotId::decode(decoder)?;
        Self::new(
            command,
            expected_snapshot,
            AttemptId::decode(decoder)?,
            ConfigurationArtifactId::decode(decoder)?,
            ConfigurationId::decode(decoder)?,
            StopCondition::decode(decoder)?,
            decoder.string_bounded(4096, "savepoint-capture-reason-bytes")?,
        )
    }
}

/// Terminal coordinator disposition of one operational savepoint capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SavepointCaptureOutcome {
    /// The scoped executor durably paused at an exact checkpoint.
    Ready,
    /// Explicit cancellation stopped the scoped capture.
    Canceled,
    /// A non-retryable worker failure stopped the scoped capture.
    Failed,
    /// The operator released a previously ready capture without selecting it.
    Discarded,
}

impl Canonical for SavepointCaptureOutcome {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::Ready => 0,
            Self::Canceled => 1,
            Self::Failed => 2,
            Self::Discarded => 3,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Ready),
            1 => Ok(Self::Canceled),
            2 => Ok(Self::Failed),
            3 => Ok(Self::Discarded),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "savepoint-capture-outcome",
                tag,
            }),
        }
    }
}

/// Idempotent owner transition resolving one operational savepoint capture.
///
/// Executor-local identities and checkpoint roots remain in the operational
/// ledger. This campaign fact records only that the coordinator authenticated
/// one terminal scoped outcome for the immutable capture request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavepointCaptureResolution {
    /// Stable caller-supplied command identity.
    pub command: CampaignCommandId,
    /// Snapshot the coordinator expects to mutate.
    pub expected_snapshot: CampaignSnapshotId,
    /// Immutable capture request fact being resolved.
    pub request: CampaignFactId,
    /// Authenticated terminal operational outcome.
    pub outcome: SavepointCaptureOutcome,
}

impl SavepointCaptureResolution {
    /// Returns a domain-separated digest of the exact resolution request.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        CampaignHash::derive(
            "crucible.campaign-savepoint-capture-resolution.v1",
            &codec::encode(self),
        )
    }
}

impl Canonical for SavepointCaptureResolution {
    fn encode(&self, encoder: &mut Encoder) {
        self.command.encode(encoder);
        self.expected_snapshot.encode(encoder);
        self.request.encode(encoder);
        self.outcome.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            command: CampaignCommandId::decode(decoder)?,
            expected_snapshot: CampaignSnapshotId::decode(decoder)?,
            request: CampaignFactId::decode(decoder)?,
            outcome: SavepointCaptureOutcome::decode(decoder)?,
        })
    }
}

/// Durable semantic admission cause for continuing one ready savepoint.
///
/// The continuation attempt carries only semantic origin and reached-boundary
/// identity. This fact separately retains the operator command and exact
/// capture/Ready provenance used to prefer one physical source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavepointContinuationSelection {
    /// Stable caller-supplied command identity.
    pub command: CampaignCommandId,
    /// Snapshot the caller expects to mutate.
    pub expected_snapshot: CampaignSnapshotId,
    /// Immutable capture request whose exact source was selected.
    pub request: CampaignFactId,
    /// Exact Ready resolution authenticating the selected request.
    pub ready: CampaignFactId,
    /// Semantic continuation admitted by this cause.
    pub continuation: AttemptId,
}

impl SavepointContinuationSelection {
    /// Returns a domain-separated digest of the exact selection command.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        CampaignHash::derive(
            "crucible.campaign-savepoint-continuation-selection.v1",
            &codec::encode(self),
        )
    }
}

impl Canonical for SavepointContinuationSelection {
    fn encode(&self, encoder: &mut Encoder) {
        self.command.encode(encoder);
        self.expected_snapshot.encode(encoder);
        self.request.encode(encoder);
        self.ready.encode(encoder);
        self.continuation.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            command: CampaignCommandId::decode(decoder)?,
            expected_snapshot: CampaignSnapshotId::decode(decoder)?,
            request: CampaignFactId::decode(decoder)?,
            ready: CampaignFactId::decode(decoder)?,
            continuation: AttemptId::decode(decoder)?,
        })
    }
}

impl DiscoveryRequest {
    /// Builds a validated explicit discovery request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an invalid stop condition.
    pub fn new(
        command: CampaignCommandId,
        expected_snapshot: CampaignSnapshotId,
        configuration: ConfigurationArtifactId,
        stop: StopCondition,
    ) -> Result<Self, CampaignCodecError> {
        stop.validate()?;
        Ok(Self {
            command,
            expected_snapshot,
            configuration,
            stop,
        })
    }

    /// Returns a domain-separated digest of the exact command payload.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        CampaignHash::derive(
            "crucible.campaign-discovery-request.v1",
            &codec::encode(self),
        )
    }

    pub(crate) const fn uses_extended_stop_schema(&self) -> bool {
        self.stop.uses_extended_wire_schema()
    }
}

impl Canonical for DiscoveryRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.command.encode(encoder);
        self.expected_snapshot.encode(encoder);
        self.configuration.encode(encoder);
        self.stop.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            CampaignCommandId::decode(decoder)?,
            CampaignSnapshotId::decode(decoder)?,
            ConfigurationArtifactId::decode(decoder)?,
            StopCondition::decode(decoder)?,
        )
    }
}

/// Explicit non-modeled terminal reason that closes an admitted attempt.
///
/// Operational retry failures do not use this type: they leave the attempt
/// claimable. These dispositions are durable coordinator decisions that close
/// a strict admission ordinal without fabricating a modeled observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NonModeledAttemptDisposition {
    /// An operator accepted cancellation before a canonical completion.
    OperatorCancelled,
    /// The admitted basis is incompatible with every eligible executor.
    PermanentlyIncompatible,
    /// Coordinator validation proved the admitted input invalid.
    InvalidInput,
    /// Policy permanently forbids the attempt from executing.
    Unauthorized,
    /// A non-retryable worker failure quarantined this admitted attempt.
    TerminalWorkerFailure,
}

impl Canonical for NonModeledAttemptDisposition {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::OperatorCancelled => 0,
            Self::PermanentlyIncompatible => 1,
            Self::InvalidInput => 2,
            Self::Unauthorized => 3,
            Self::TerminalWorkerFailure => 4,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::OperatorCancelled),
            1 => Ok(Self::PermanentlyIncompatible),
            2 => Ok(Self::InvalidInput),
            3 => Ok(Self::Unauthorized),
            4 => Ok(Self::TerminalWorkerFailure),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "non-modeled-attempt-disposition",
                tag,
            }),
        }
    }
}

/// Immutable causal fact from which campaign projections are rebuilt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CampaignFact {
    /// A new named campaign history was rooted at an authenticated snapshot.
    CampaignDerived(CampaignDerivation),
    /// A stable runtime choice occurrence was discovered at one exact parent.
    ChoiceOpportunityDiscovered {
        /// Exact parent artifact at which the opportunity occurs.
        parent: ConfigurationArtifactId,
        /// Semantic branch point derived from the parent and opportunity.
        branch_point: BranchPointId,
        /// Exact presentation-bearing opportunity.
        opportunity: ChoiceOpportunityId,
    },
    /// A bounded finite or generated branch request was issued.
    BranchRequestIssued(BranchRequestId),
    /// A branch request was accepted with snapshot-bound cardinality and budget counts.
    BranchRequestAccepted {
        /// Exact immutable branch request.
        request: BranchRequestId,
        /// Owner-derived summary bound into this transition fact.
        summary: BranchAcceptanceSummary,
    },
    /// A coordinator-validated planner step advanced planning state.
    PlannerAdvanced(PlannerStepId),
    /// A candidate proposal was issued.
    ProposalIssued(ProposalId),
    /// A semantic attempt received an execution basis or additional cause.
    AttemptAdmitted(AttemptAdmissionId),
    /// A coordinator decision closed an ordinal without a modeled observation.
    AttemptClosed {
        /// Admitted semantic attempt.
        attempt: AttemptId,
        /// The exact ordinal closed by this fact.
        ordinal: AdmissionOrdinal,
        /// Explicit non-modeled terminal reason.
        disposition: NonModeledAttemptDisposition,
    },
    /// A canonical observation completed an attempt.
    ObservationPublished(ObservationId),
    /// A canonical observation completed an attempt with scoped feedback ownership.
    ObservationCredited(ObservationId),
    /// A stable finding and reproduction closure was published.
    FindingPublished(FindingId),
    /// One policy-bound objective evaluation became authoritative.
    ObjectiveEvaluationPublished(ObjectiveEvaluationId),
    /// A future policy revision became active.
    PolicyActivated(PolicyActivation),
    /// Additive semantic budget was granted.
    BudgetGranted(BudgetGrant),
    /// Idempotent lifecycle or steering command was accepted.
    ControlRequested(ControlRequest),
    /// Semantic retention intent changed.
    PinChanged(PinChange),
    /// Idempotent semantic retention command was accepted.
    PinCommandAccepted(PinRequest),
    /// Idempotent explicit campaign-owned configuration discovery was accepted.
    DiscoveryRequested(DiscoveryRequest),
    /// Idempotent attempt-stop savepoint capture was accepted.
    SavepointCaptureRequested(SavepointCaptureRequest),
    /// One accepted savepoint capture reached a terminal operational outcome.
    SavepointCaptureResolved(SavepointCaptureResolution),
    /// One ready savepoint was selected as a semantic continuation cause.
    SavepointContinuationSelected(SavepointContinuationSelection),
}

impl CampaignFact {
    pub(crate) const fn schema_version(&self) -> u32 {
        match self {
            Self::CampaignDerived(_) => DERIVATION_CAMPAIGN_FACT_SCHEMA_VERSION,
            Self::ObservationCredited(_) => CREDITED_OBSERVATION_CAMPAIGN_FACT_SCHEMA_VERSION,
            Self::PinCommandAccepted(_) => PIN_COMMAND_CAMPAIGN_FACT_SCHEMA_VERSION,
            Self::ObjectiveEvaluationPublished(_) => CAMPAIGN_FACT_SCHEMA_VERSION,
            Self::BranchRequestAccepted { .. } => BRANCH_ACCEPTANCE_CAMPAIGN_FACT_SCHEMA_VERSION,
            Self::DiscoveryRequested(request) if request.uses_extended_stop_schema() => {
                EXTENDED_STOP_DISCOVERY_REQUEST_CAMPAIGN_FACT_SCHEMA_VERSION
            }
            Self::DiscoveryRequested(_) => DISCOVERY_REQUEST_CAMPAIGN_FACT_SCHEMA_VERSION,
            Self::AttemptClosed {
                disposition: NonModeledAttemptDisposition::TerminalWorkerFailure,
                ..
            } => TERMINAL_WORKER_FAILURE_CAMPAIGN_FACT_SCHEMA_VERSION,
            Self::SavepointCaptureRequested(_) => SAVEPOINT_CAPTURE_CAMPAIGN_FACT_SCHEMA_VERSION,
            Self::SavepointCaptureResolved(_) => {
                SAVEPOINT_CAPTURE_RESOLUTION_CAMPAIGN_FACT_SCHEMA_VERSION
            }
            Self::SavepointContinuationSelected(_) => {
                SAVEPOINT_CONTINUATION_SELECTION_CAMPAIGN_FACT_SCHEMA_VERSION
            }
            _ => LEGACY_CAMPAIGN_FACT_SCHEMA_VERSION,
        }
    }

    /// Returns strict canonical fact bytes including the schema version.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        self.schema_version().encode(&mut encoder);
        self.encode(&mut encoder);
        encoder.finish()
    }

    /// Decodes strict canonical fact bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, oversized,
    /// or unknown-version input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        #[derive(Clone, Debug, PartialEq, Eq)]
        struct VersionedFact {
            version: u32,
            fact: CampaignFact,
        }

        impl Canonical for VersionedFact {
            fn encode(&self, encoder: &mut Encoder) {
                self.version.encode(encoder);
                self.fact.encode(encoder);
            }

            fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
                let version = u32::decode(decoder)?;
                match version {
                    LEGACY_CAMPAIGN_FACT_SCHEMA_VERSION => {
                        CampaignFact::decode_versioned(decoder, CampaignFactDecodeExtension::None)
                            .map(|fact| Self { version, fact })
                    }
                    DERIVATION_CAMPAIGN_FACT_SCHEMA_VERSION => {
                        let fact = CampaignFact::decode_versioned(
                            decoder,
                            CampaignFactDecodeExtension::Derivation,
                        )?;
                        if !matches!(fact, CampaignFact::CampaignDerived(_)) {
                            return Err(CampaignCodecError::InvalidValue {
                                reason: "campaign fact variant requires its original schema version",
                            });
                        }
                        Ok(Self { version, fact })
                    }
                    CREDITED_OBSERVATION_CAMPAIGN_FACT_SCHEMA_VERSION => {
                        let fact = CampaignFact::decode_versioned(
                            decoder,
                            CampaignFactDecodeExtension::CreditedObservation,
                        )?;
                        if !matches!(fact, CampaignFact::ObservationCredited(_)) {
                            return Err(CampaignCodecError::InvalidValue {
                                reason: "campaign fact variant requires its original schema version",
                            });
                        }
                        Ok(Self { version, fact })
                    }
                    PIN_COMMAND_CAMPAIGN_FACT_SCHEMA_VERSION => {
                        let fact = CampaignFact::decode_versioned(
                            decoder,
                            CampaignFactDecodeExtension::PinCommand,
                        )?;
                        if !matches!(fact, CampaignFact::PinCommandAccepted(_)) {
                            return Err(CampaignCodecError::InvalidValue {
                                reason: "campaign fact variant requires its original schema version",
                            });
                        }
                        Ok(Self { version, fact })
                    }
                    CAMPAIGN_FACT_SCHEMA_VERSION => {
                        let fact = CampaignFact::decode_versioned(
                            decoder,
                            CampaignFactDecodeExtension::ObjectiveEvaluation,
                        )?;
                        if !matches!(fact, CampaignFact::ObjectiveEvaluationPublished(_)) {
                            return Err(CampaignCodecError::InvalidValue {
                                reason: "campaign fact variant requires its original schema version",
                            });
                        }
                        Ok(Self { version, fact })
                    }
                    BRANCH_ACCEPTANCE_CAMPAIGN_FACT_SCHEMA_VERSION => {
                        let fact = CampaignFact::decode_versioned(
                            decoder,
                            CampaignFactDecodeExtension::BranchAcceptance,
                        )?;
                        if !matches!(fact, CampaignFact::BranchRequestAccepted { .. }) {
                            return Err(CampaignCodecError::InvalidValue {
                                reason: "campaign fact variant requires its original schema version",
                            });
                        }
                        Ok(Self { version, fact })
                    }
                    DISCOVERY_REQUEST_CAMPAIGN_FACT_SCHEMA_VERSION => {
                        let fact = CampaignFact::decode_versioned(
                            decoder,
                            CampaignFactDecodeExtension::DiscoveryRequest,
                        )?;
                        if !matches!(
                            fact,
                            CampaignFact::DiscoveryRequested(ref request)
                                if !request.uses_extended_stop_schema()
                        ) {
                            return Err(CampaignCodecError::InvalidValue {
                                reason: "campaign fact variant requires its original schema version",
                            });
                        }
                        Ok(Self { version, fact })
                    }
                    EXTENDED_STOP_DISCOVERY_REQUEST_CAMPAIGN_FACT_SCHEMA_VERSION => {
                        let fact = CampaignFact::decode_versioned(
                            decoder,
                            CampaignFactDecodeExtension::DiscoveryRequest,
                        )?;
                        if !matches!(
                            fact,
                            CampaignFact::DiscoveryRequested(ref request)
                                if request.uses_extended_stop_schema()
                        ) {
                            return Err(CampaignCodecError::InvalidValue {
                                reason: "campaign fact variant requires its original schema version",
                            });
                        }
                        Ok(Self { version, fact })
                    }
                    TERMINAL_WORKER_FAILURE_CAMPAIGN_FACT_SCHEMA_VERSION => {
                        let fact = CampaignFact::decode_versioned(
                            decoder,
                            CampaignFactDecodeExtension::TerminalWorkerFailure,
                        )?;
                        if !matches!(
                            fact,
                            CampaignFact::AttemptClosed {
                                disposition: NonModeledAttemptDisposition::TerminalWorkerFailure,
                                ..
                            }
                        ) {
                            return Err(CampaignCodecError::InvalidValue {
                                reason: "campaign fact variant requires its original schema version",
                            });
                        }
                        Ok(Self { version, fact })
                    }
                    SAVEPOINT_CAPTURE_CAMPAIGN_FACT_SCHEMA_VERSION => {
                        let fact = CampaignFact::decode_versioned(
                            decoder,
                            CampaignFactDecodeExtension::SavepointCapture,
                        )?;
                        if !matches!(fact, CampaignFact::SavepointCaptureRequested(_)) {
                            return Err(CampaignCodecError::InvalidValue {
                                reason: "campaign fact variant requires its original schema version",
                            });
                        }
                        Ok(Self { version, fact })
                    }
                    SAVEPOINT_CAPTURE_RESOLUTION_CAMPAIGN_FACT_SCHEMA_VERSION => {
                        let fact = CampaignFact::decode_versioned(
                            decoder,
                            CampaignFactDecodeExtension::SavepointCaptureResolution,
                        )?;
                        if !matches!(fact, CampaignFact::SavepointCaptureResolved(_)) {
                            return Err(CampaignCodecError::InvalidValue {
                                reason: "campaign fact variant requires its original schema version",
                            });
                        }
                        Ok(Self { version, fact })
                    }
                    SAVEPOINT_CONTINUATION_SELECTION_CAMPAIGN_FACT_SCHEMA_VERSION => {
                        let fact = CampaignFact::decode_versioned(
                            decoder,
                            CampaignFactDecodeExtension::SavepointContinuationSelection,
                        )?;
                        if !matches!(fact, CampaignFact::SavepointContinuationSelected(_)) {
                            return Err(CampaignCodecError::InvalidValue {
                                reason: "campaign fact variant requires its original schema version",
                            });
                        }
                        Ok(Self { version, fact })
                    }
                    _ => Err(CampaignCodecError::InvalidValue {
                        reason: "unsupported campaign object schema version",
                    }),
                }
            }
        }

        codec::decode::<VersionedFact>(bytes).map(|versioned| versioned.fact)
    }

    /// Returns the domain-separated immutable fact identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<CampaignFactId, CampaignCodecError> {
        CampaignFactId::from_content_id(crate::ObjectEnvelope::for_fact(self)?.content_id())
    }
}

impl Canonical for CampaignFact {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::CampaignDerived(derivation) => {
                encoder.u8(12);
                derivation.encode(encoder);
            }
            Self::ChoiceOpportunityDiscovered {
                parent,
                branch_point,
                opportunity,
            } => {
                encoder.u8(0);
                parent.encode(encoder);
                branch_point.encode(encoder);
                opportunity.encode(encoder);
            }
            Self::BranchRequestIssued(id) => {
                encoder.u8(1);
                id.encode(encoder);
            }
            Self::BranchRequestAccepted { request, summary } => {
                encoder.u8(16);
                request.encode(encoder);
                summary.encode(encoder);
            }
            Self::PlannerAdvanced(id) => {
                encoder.u8(2);
                id.encode(encoder);
            }
            Self::ProposalIssued(id) => {
                encoder.u8(3);
                id.encode(encoder);
            }
            Self::AttemptAdmitted(admission) => {
                encoder.u8(4);
                admission.encode(encoder);
            }
            Self::ObservationPublished(id) => {
                encoder.u8(5);
                id.encode(encoder);
            }
            Self::ObservationCredited(id) => {
                encoder.u8(13);
                id.encode(encoder);
            }
            Self::FindingPublished(id) => {
                encoder.u8(6);
                id.encode(encoder);
            }
            Self::ObjectiveEvaluationPublished(id) => {
                encoder.u8(15);
                id.encode(encoder);
            }
            Self::PolicyActivated(activation) => {
                encoder.u8(7);
                activation.encode(encoder);
            }
            Self::BudgetGranted(grant) => {
                encoder.u8(8);
                grant.encode(encoder);
            }
            Self::ControlRequested(request) => {
                encoder.u8(9);
                request.encode(encoder);
            }
            Self::PinChanged(change) => {
                encoder.u8(10);
                change.encode(encoder);
            }
            Self::PinCommandAccepted(request) => {
                encoder.u8(14);
                request.encode(encoder);
            }
            Self::DiscoveryRequested(request) => {
                encoder.u8(17);
                request.encode(encoder);
            }
            Self::SavepointCaptureRequested(request) => {
                encoder.u8(18);
                request.encode(encoder);
            }
            Self::SavepointCaptureResolved(resolution) => {
                encoder.u8(19);
                resolution.encode(encoder);
            }
            Self::SavepointContinuationSelected(selection) => {
                encoder.u8(20);
                selection.encode(encoder);
            }
            Self::AttemptClosed {
                attempt,
                ordinal,
                disposition,
            } => {
                encoder.u8(11);
                attempt.encode(encoder);
                ordinal.encode(encoder);
                disposition.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::decode_versioned(decoder, CampaignFactDecodeExtension::All)
    }
}

impl CampaignFact {
    fn decode_versioned(
        decoder: &mut Decoder<'_>,
        extension: CampaignFactDecodeExtension,
    ) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::ChoiceOpportunityDiscovered {
                parent: ConfigurationArtifactId::decode(decoder)?,
                branch_point: BranchPointId::decode(decoder)?,
                opportunity: ChoiceOpportunityId::decode(decoder)?,
            }),
            1 => BranchRequestId::decode(decoder).map(Self::BranchRequestIssued),
            2 => PlannerStepId::decode(decoder).map(Self::PlannerAdvanced),
            3 => ProposalId::decode(decoder).map(Self::ProposalIssued),
            4 => AttemptAdmissionId::decode(decoder).map(Self::AttemptAdmitted),
            5 => ObservationId::decode(decoder).map(Self::ObservationPublished),
            6 => FindingId::decode(decoder).map(Self::FindingPublished),
            7 => PolicyActivation::decode(decoder).map(Self::PolicyActivated),
            8 => BudgetGrant::decode(decoder).map(Self::BudgetGranted),
            9 => ControlRequest::decode(decoder).map(Self::ControlRequested),
            10 => PinChange::decode(decoder).map(Self::PinChanged),
            11 => {
                let attempt = AttemptId::decode(decoder)?;
                let ordinal = AdmissionOrdinal::decode(decoder)?;
                let disposition = NonModeledAttemptDisposition::decode(decoder)?;
                if disposition == NonModeledAttemptDisposition::TerminalWorkerFailure
                    && !matches!(
                        extension,
                        CampaignFactDecodeExtension::TerminalWorkerFailure
                            | CampaignFactDecodeExtension::All
                    )
                {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "terminal worker failure disposition requires campaign fact v10",
                    });
                }
                Ok(Self::AttemptClosed {
                    attempt,
                    ordinal,
                    disposition,
                })
            }
            12 if matches!(
                extension,
                CampaignFactDecodeExtension::Derivation | CampaignFactDecodeExtension::All
            ) =>
            {
                CampaignDerivation::decode(decoder).map(Self::CampaignDerived)
            }
            13 if matches!(
                extension,
                CampaignFactDecodeExtension::CreditedObservation | CampaignFactDecodeExtension::All
            ) =>
            {
                ObservationId::decode(decoder).map(Self::ObservationCredited)
            }
            14 if matches!(
                extension,
                CampaignFactDecodeExtension::PinCommand | CampaignFactDecodeExtension::All
            ) =>
            {
                PinRequest::decode(decoder).map(Self::PinCommandAccepted)
            }
            15 if matches!(
                extension,
                CampaignFactDecodeExtension::ObjectiveEvaluation | CampaignFactDecodeExtension::All
            ) =>
            {
                ObjectiveEvaluationId::decode(decoder).map(Self::ObjectiveEvaluationPublished)
            }
            16 if matches!(
                extension,
                CampaignFactDecodeExtension::BranchAcceptance | CampaignFactDecodeExtension::All
            ) =>
            {
                Ok(Self::BranchRequestAccepted {
                    request: BranchRequestId::decode(decoder)?,
                    summary: BranchAcceptanceSummary::decode(decoder)?,
                })
            }
            17 if matches!(
                extension,
                CampaignFactDecodeExtension::DiscoveryRequest | CampaignFactDecodeExtension::All
            ) =>
            {
                DiscoveryRequest::decode(decoder).map(Self::DiscoveryRequested)
            }
            18 if matches!(
                extension,
                CampaignFactDecodeExtension::SavepointCapture | CampaignFactDecodeExtension::All
            ) =>
            {
                SavepointCaptureRequest::decode(decoder).map(Self::SavepointCaptureRequested)
            }
            19 if matches!(
                extension,
                CampaignFactDecodeExtension::SavepointCaptureResolution
                    | CampaignFactDecodeExtension::All
            ) =>
            {
                SavepointCaptureResolution::decode(decoder).map(Self::SavepointCaptureResolved)
            }
            20 if matches!(
                extension,
                CampaignFactDecodeExtension::SavepointContinuationSelection
                    | CampaignFactDecodeExtension::All
            ) =>
            {
                SavepointContinuationSelection::decode(decoder)
                    .map(Self::SavepointContinuationSelected)
            }
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "campaign-fact",
                tag,
            }),
        }
    }
}
