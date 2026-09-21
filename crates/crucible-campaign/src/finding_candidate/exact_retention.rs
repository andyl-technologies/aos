//! Policy-bound automatic exact-checkpoint retention evidence.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// Maximum authenticated exact-checkpoint candidates considered for one finding.
pub const MAX_FINDING_EXACT_RETENTION_CANDIDATES: u32 = 4_096;

/// Stable reason automatic exact retention could not complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingExactRetentionIncomplete {
    /// No producer could capture the required canonical safe-stop boundaries.
    MissingSafeBoundaryCapture,
    /// The protected operational candidate inventory could not be read.
    CandidateInventoryUnavailable,
    /// More candidates existed than the bounded selector may authenticate.
    CandidateLimitExceeded,
    /// A candidate failed exact configuration or scheduler authentication.
    CandidateAuthenticationFailed,
    /// Deterministic role selection failed after candidate authentication.
    SelectionFailed,
}

impl Canonical for FindingExactRetentionIncomplete {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::MissingSafeBoundaryCapture => 0,
            Self::CandidateInventoryUnavailable => 1,
            Self::CandidateLimitExceeded => 2,
            Self::CandidateAuthenticationFailed => 3,
            Self::SelectionFailed => 4,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::MissingSafeBoundaryCapture),
            1 => Ok(Self::CandidateInventoryUnavailable),
            2 => Ok(Self::CandidateLimitExceeded),
            3 => Ok(Self::CandidateAuthenticationFailed),
            4 => Ok(Self::SelectionFailed),
            6 => Err(CampaignCodecError::InvalidValue {
                reason: "finding retention records must include the current policy",
            }),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "finding-exact-retention-incomplete",
                tag,
            }),
        }
    }
}

/// Closed outcome of the active policy's automatic exact-retention decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingExactRetentionDisposition {
    /// The active policy did not request exact finding retention.
    Disabled,
    /// Every safely eligible requested role was captured, selected, and staged.
    Complete,
    /// Thin evidence remains publishable, but exact retention did not complete.
    Incomplete(FindingExactRetentionIncomplete),
}

impl Canonical for FindingExactRetentionDisposition {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Disabled => encoder.u8(0),
            Self::Complete => encoder.u8(1),
            Self::Incomplete(reason) => {
                encoder.u8(2);
                reason.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Disabled),
            1 => Ok(Self::Complete),
            2 => Ok(Self::Incomplete(FindingExactRetentionIncomplete::decode(
                decoder,
            )?)),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "finding-exact-retention-disposition",
                tag,
            }),
        }
    }
}

/// Active-policy basis and bounded outcome for automatic exact finding retention.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingExactRetention {
    snapshot: CampaignSnapshotId,
    policy: CampaignPolicyId,
    admission: AttemptAdmissionId,
    authenticated_candidates: u32,
    disposition: FindingExactRetentionDisposition,
}

impl FindingExactRetention {
    /// Builds one policy-bound automatic exact-retention outcome.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::LimitExceeded`] when the authenticated
    /// candidate count exceeds 4,096.
    pub fn new(
        snapshot: CampaignSnapshotId,
        policy: CampaignPolicyId,
        admission: AttemptAdmissionId,
        authenticated_candidates: u32,
        disposition: FindingExactRetentionDisposition,
    ) -> Result<Self, CampaignCodecError> {
        if authenticated_candidates > MAX_FINDING_EXACT_RETENTION_CANDIDATES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-exact-retention-candidate-count",
            });
        }
        if disposition == FindingExactRetentionDisposition::Disabled
            && authenticated_candidates != 0
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "disabled finding exact retention has authenticated candidates",
            });
        }
        if matches!(disposition, FindingExactRetentionDisposition::Incomplete(_))
            && authenticated_candidates != 0
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "incomplete finding exact retention has authenticated candidates",
            });
        }
        Ok(Self {
            snapshot,
            policy,
            admission,
            authenticated_candidates,
            disposition,
        })
    }

    /// Returns the immutable snapshot that selected the execution-basis admission.
    #[must_use]
    pub const fn snapshot(self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the authenticated active policy that decided retention.
    #[must_use]
    pub const fn policy(self) -> CampaignPolicyId {
        self.policy
    }

    /// Returns the execution-basis admission governed by the policy decision.
    #[must_use]
    pub const fn admission(self) -> AttemptAdmissionId {
        self.admission
    }

    /// Returns the number of exact candidates authenticated by the selector.
    #[must_use]
    pub const fn authenticated_candidates(self) -> u32 {
        self.authenticated_candidates
    }

    /// Returns the closed exact-retention outcome.
    #[must_use]
    pub const fn disposition(self) -> FindingExactRetentionDisposition {
        self.disposition
    }
}

impl Canonical for FindingExactRetention {
    fn encode(&self, encoder: &mut Encoder) {
        self.snapshot.encode(encoder);
        Some(self.policy).encode(encoder);
        self.admission.encode(encoder);
        self.authenticated_candidates.encode(encoder);
        self.disposition.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let snapshot = CampaignSnapshotId::decode(decoder)?;
        let policy = Option::<CampaignPolicyId>::decode(decoder)?.ok_or(
            CampaignCodecError::InvalidValue {
                reason: "finding exact retention requires a policy",
            },
        )?;
        Self::new(
            snapshot,
            policy,
            AttemptAdmissionId::decode(decoder)?,
            u32::decode(decoder)?,
            FindingExactRetentionDisposition::decode(decoder)?,
        )
    }
}

/// One production checkpoint and its authenticated scheduler event boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingExactRetentionCandidate {
    checkpoint: ExactCheckpointId,
    event_count: u64,
}

impl FindingExactRetentionCandidate {
    /// Creates one candidate projection authenticated from immutable checkpoint bytes.
    #[must_use]
    pub const fn new(checkpoint: ExactCheckpointId, event_count: u64) -> Self {
        Self {
            checkpoint,
            event_count,
        }
    }

    /// Returns the production checkpoint root.
    #[must_use]
    pub const fn checkpoint(self) -> ExactCheckpointId {
        self.checkpoint
    }

    /// Returns the scheduler event count at the checkpoint boundary.
    #[must_use]
    pub const fn event_count(self) -> u64 {
        self.event_count
    }
}

impl Canonical for FindingExactRetentionCandidate {
    fn encode(&self, encoder: &mut Encoder) {
        self.checkpoint.encode(encoder);
        self.event_count.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self::new(
            ExactCheckpointId::decode(decoder)?,
            u64::decode(decoder)?,
        ))
    }
}

/// Authenticated candidate inventory and deterministic exact-pin selection proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingExactRetentionEvidence {
    candidates: Vec<FindingExactRetentionCandidate>,
    captured_failure: ExactCheckpointId,
    failure_events: u64,
    measurement_boundary_events: Option<u64>,
    selected: FindingExactPins,
}

impl FindingExactRetentionEvidence {
    /// Selects the canonical retained roles from one authenticated inventory.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the inventory or boundaries are
    /// invalid, including when the failure checkpoint is absent.
    pub fn select(
        candidates: Vec<FindingExactRetentionCandidate>,
        captured_failure: ExactCheckpointId,
        failure_events: u64,
        measurement_boundary_events: Option<u64>,
    ) -> Result<Self, CampaignCodecError> {
        let indexed = candidates
            .iter()
            .map(|candidate| (candidate.checkpoint(), candidate.event_count()))
            .collect::<BTreeMap<_, _>>();
        let greatest = |boundary: u64, strict: bool| {
            indexed
                .iter()
                .filter(|(_, events)| {
                    if strict {
                        **events < boundary
                    } else {
                        **events <= boundary
                    }
                })
                .max_by(|(left_root, left_events), (right_root, right_events)| {
                    left_events
                        .cmp(right_events)
                        .then_with(|| right_root.cmp(left_root))
                })
                .map(|(root, _)| *root)
        };
        let post = indexed
            .iter()
            .filter(|(_, events)| **events >= failure_events)
            .min_by(|(left_root, left_events), (right_root, right_events)| {
                left_events
                    .cmp(right_events)
                    .then_with(|| left_root.cmp(right_root))
            })
            .map(|(root, _)| *root);
        let selected = FindingExactPins::new(
            greatest(failure_events, true).into_iter().collect(),
            measurement_boundary_events
                .and_then(|boundary| greatest(boundary, false))
                .into_iter()
                .collect(),
            post.into_iter().collect(),
            BTreeSet::new(),
        )?;
        Self::new(
            candidates,
            captured_failure,
            failure_events,
            measurement_boundary_events,
            selected,
        )
    }

    /// Builds a bounded canonical selector proof over production roots.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an empty, unsorted, duplicate, or
    /// oversized inventory, a missing captured root, or invalid boundaries.
    pub fn new(
        candidates: Vec<FindingExactRetentionCandidate>,
        captured_failure: ExactCheckpointId,
        failure_events: u64,
        measurement_boundary_events: Option<u64>,
        selected: FindingExactPins,
    ) -> Result<Self, CampaignCodecError> {
        if candidates.is_empty()
            || candidates.len() > MAX_FINDING_EXACT_RETENTION_CANDIDATES as usize
        {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-exact-retention-candidate-count",
            });
        }
        if candidates
            .windows(2)
            .any(|pair| pair[0].checkpoint() >= pair[1].checkpoint())
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding exact retention candidates are not strictly sorted",
            });
        }
        if candidates
            .iter()
            .filter(|candidate| candidate.checkpoint() == captured_failure)
            .count()
            != 1
            || !candidates.iter().any(|candidate| {
                candidate.checkpoint() == captured_failure
                    && candidate.event_count() == failure_events
            })
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding exact retention captured failure boundary is invalid",
            });
        }
        if measurement_boundary_events.is_some_and(|events| events > failure_events) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding exact retention measurement boundary follows failure",
            });
        }

        Ok(Self {
            candidates,
            captured_failure,
            failure_events,
            measurement_boundary_events,
            selected,
        })
    }

    /// Returns the complete sorted eligible candidate inventory.
    #[must_use]
    pub fn candidates(&self) -> &[FindingExactRetentionCandidate] {
        &self.candidates
    }

    /// Returns the checkpoint captured at the failure boundary.
    #[must_use]
    pub const fn captured_failure(&self) -> ExactCheckpointId {
        self.captured_failure
    }

    /// Returns the authenticated failure event boundary.
    #[must_use]
    pub const fn failure_events(&self) -> u64 {
        self.failure_events
    }

    /// Returns the authenticated successful-measurement boundary.
    #[must_use]
    pub const fn measurement_boundary_events(&self) -> Option<u64> {
        self.measurement_boundary_events
    }

    /// Returns the role selection derived by the producer.
    #[must_use]
    pub const fn selected(&self) -> &FindingExactPins {
        &self.selected
    }
}

impl Canonical for FindingExactRetentionEvidence {
    fn encode(&self, encoder: &mut Encoder) {
        self.candidates.encode(encoder);
        self.captured_failure.encode(encoder);
        self.failure_events.encode(encoder);
        self.measurement_boundary_events.encode(encoder);
        self.selected.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            Vec::<FindingExactRetentionCandidate>::decode(decoder)?,
            ExactCheckpointId::decode(decoder)?,
            u64::decode(decoder)?,
            Option::<u64>::decode(decoder)?,
            FindingExactPins::decode(decoder)?,
        )
    }
}
