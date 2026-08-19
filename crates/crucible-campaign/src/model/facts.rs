//! Lifecycle commands and immutable causal campaign facts.

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::{
    AttemptId, BranchRequestId, CampaignCodecError, CampaignCommandId, CampaignFactId,
    CampaignHash, CampaignPolicyId, CampaignSnapshotId, ChoiceOpportunityId, ConfigurationId,
    FindingId, ObservationId, PlannerStepId, ProposalId,
};

use super::AdmissionOrdinal;

const CAMPAIGN_FACT_SCHEMA_VERSION: u32 = 1;

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
    /// Returns [`CampaignCodecError`] for an oversized, NUL-containing, or
    /// non-normalized reason.
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
}

impl Canonical for NonModeledAttemptDisposition {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::OperatorCancelled => 0,
            Self::PermanentlyIncompatible => 1,
            Self::InvalidInput => 2,
            Self::Unauthorized => 3,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::OperatorCancelled),
            1 => Ok(Self::PermanentlyIncompatible),
            2 => Ok(Self::InvalidInput),
            3 => Ok(Self::Unauthorized),
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
    /// A stable runtime choice occurrence was discovered.
    ChoiceOpportunityDiscovered(ChoiceOpportunityId),
    /// A bounded finite or generated branch request was issued.
    BranchRequestIssued(BranchRequestId),
    /// A coordinator-validated planner step advanced planning state.
    PlannerAdvanced(PlannerStepId),
    /// A candidate proposal was issued.
    ProposalIssued(ProposalId),
    /// A semantic attempt received its unique execution basis.
    AttemptAdmitted {
        /// Admitted semantic attempt.
        attempt: AttemptId,
        /// Global strict-mode order.
        ordinal: AdmissionOrdinal,
    },
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
    /// A stable finding and reproduction closure was published.
    FindingPublished(FindingId),
    /// A future policy revision became active.
    PolicyActivated(PolicyActivation),
    /// Additive semantic budget was granted.
    BudgetGranted(BudgetGrant),
    /// Idempotent lifecycle or steering command was accepted.
    ControlRequested(ControlRequest),
    /// Semantic retention intent changed.
    PinChanged(PinChange),
}

impl CampaignFact {
    /// Returns strict canonical fact bytes including the schema version.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        CAMPAIGN_FACT_SCHEMA_VERSION.encode(&mut encoder);
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
        struct VersionedFact(CampaignFact);

        impl Canonical for VersionedFact {
            fn encode(&self, encoder: &mut Encoder) {
                CAMPAIGN_FACT_SCHEMA_VERSION.encode(encoder);
                self.0.encode(encoder);
            }

            fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
                require_schema(
                    u32::decode(decoder)?,
                    CAMPAIGN_FACT_SCHEMA_VERSION,
                    "campaign-fact",
                )?;
                CampaignFact::decode(decoder).map(Self)
            }
        }

        codec::decode::<VersionedFact>(bytes).map(|fact| fact.0)
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
            Self::ChoiceOpportunityDiscovered(id) => {
                encoder.u8(0);
                id.encode(encoder);
            }
            Self::BranchRequestIssued(id) => {
                encoder.u8(1);
                id.encode(encoder);
            }
            Self::PlannerAdvanced(id) => {
                encoder.u8(2);
                id.encode(encoder);
            }
            Self::ProposalIssued(id) => {
                encoder.u8(3);
                id.encode(encoder);
            }
            Self::AttemptAdmitted { attempt, ordinal } => {
                encoder.u8(4);
                attempt.encode(encoder);
                ordinal.encode(encoder);
            }
            Self::ObservationPublished(id) => {
                encoder.u8(5);
                id.encode(encoder);
            }
            Self::FindingPublished(id) => {
                encoder.u8(6);
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
        match decoder.u8()? {
            0 => ChoiceOpportunityId::decode(decoder).map(Self::ChoiceOpportunityDiscovered),
            1 => BranchRequestId::decode(decoder).map(Self::BranchRequestIssued),
            2 => PlannerStepId::decode(decoder).map(Self::PlannerAdvanced),
            3 => ProposalId::decode(decoder).map(Self::ProposalIssued),
            4 => Ok(Self::AttemptAdmitted {
                attempt: AttemptId::decode(decoder)?,
                ordinal: AdmissionOrdinal::decode(decoder)?,
            }),
            5 => ObservationId::decode(decoder).map(Self::ObservationPublished),
            6 => FindingId::decode(decoder).map(Self::FindingPublished),
            7 => PolicyActivation::decode(decoder).map(Self::PolicyActivated),
            8 => BudgetGrant::decode(decoder).map(Self::BudgetGranted),
            9 => ControlRequest::decode(decoder).map(Self::ControlRequested),
            10 => PinChange::decode(decoder).map(Self::PinChanged),
            11 => Ok(Self::AttemptClosed {
                attempt: AttemptId::decode(decoder)?,
                ordinal: AdmissionOrdinal::decode(decoder)?,
                disposition: NonModeledAttemptDisposition::decode(decoder)?,
            }),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "campaign-fact",
                tag,
            }),
        }
    }
}

fn require_schema(
    actual: u32,
    expected: u32,
    _kind: &'static str,
) -> Result<(), CampaignCodecError> {
    if actual == expected {
        Ok(())
    } else {
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported campaign object schema version",
        })
    }
}
