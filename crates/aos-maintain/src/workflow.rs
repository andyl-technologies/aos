//! Durable workflow states, hash-chained events, and transient progress.

use anyhow::{Result, bail};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::identity::{OperationId, RunId};
use crate::{MAINTENANCE_JOURNAL_EVENT_V1, MAINTENANCE_PROGRESS_EVENT_V1};

/// Enumerates every durable maintenance-run state without collapsing axes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunState {
    /// Fresh discovery evidence has been bound to the run.
    Observed,
    /// A complete candidate vector has been selected.
    Selected,
    /// Immutable campaign and gate intent has been frozen.
    Planned,
    /// A clean isolated worktree exists at the planned base.
    WorktreeReady,
    /// Declared sources or generated inputs are being materialized.
    Materializing,
    /// The exact semantic and repository diff satisfies policy.
    PolicyValid,
    /// The exact attempt passed the quick gate plan.
    QuickGated,
    /// A bounded repair iteration is active or awaiting acceptance.
    Repairing,
    /// The maintainer accepted the exact candidate tree.
    CandidateAccepted,
    /// The accepted candidate has an exact local commit.
    Committed,
    /// The exact candidate commit passed every final local gate.
    FinalGated,
    /// Evidence and reviewed PR material are complete.
    ReadyForPr,
    /// The exact branch head and PR were published explicitly.
    PrPublished,
    /// The published PR is waiting for fail-closed authorization evidence.
    AwaitingRemoteAuthorization,
    /// Remote observations prove the exact head merge-eligible.
    MergeEligibleObserved,
    /// Remote observations prove the protected merge identity.
    MergedObserved,
    /// The protected merge identity is ready for RFC-0017 consumption.
    ReleaseHandoff,
    /// No acceptable newer candidate exists.
    NoChange,
    /// A newer compatible candidate replaced this unreviewed run.
    Superseded,
    /// Scope, legal, policy, or design input is required.
    BlockedHuman,
    /// Source identity or assurance evidence conflicts.
    Quarantined,
    /// The maintainer rejected the candidate or patch.
    Rejected,
    /// The maintainer intentionally stopped and retained the run.
    Abandoned,
    /// A terminal policy or infrastructure failure exhausted its budget.
    Failed,
}

impl RunState {
    /// Reports whether `next` is a legal direct durable transition.
    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        use RunState::{
            Abandoned, AwaitingRemoteAuthorization, BlockedHuman, CandidateAccepted, Committed,
            Failed, FinalGated, Materializing, MergeEligibleObserved, MergedObserved, NoChange,
            Observed, Planned, PolicyValid, PrPublished, Quarantined, QuickGated, ReadyForPr,
            Rejected, ReleaseHandoff, Repairing, Selected, Superseded, WorktreeReady,
        };

        let normal = matches!(
            (self, next),
            (Observed, Selected)
                | (Selected, Planned)
                | (Planned, WorktreeReady)
                | (WorktreeReady, Materializing)
                | (Materializing, PolicyValid)
                | (PolicyValid, QuickGated)
                | (QuickGated, Repairing)
                | (QuickGated, CandidateAccepted)
                | (Repairing, PolicyValid)
                | (Repairing, CandidateAccepted)
                | (CandidateAccepted, Committed)
                | (Committed, FinalGated)
                | (FinalGated, ReadyForPr)
                | (ReadyForPr, PrPublished)
                | (PrPublished, AwaitingRemoteAuthorization)
                | (AwaitingRemoteAuthorization, MergeEligibleObserved)
                | (MergeEligibleObserved, MergedObserved)
                | (MergedObserved, ReleaseHandoff)
        );
        if normal {
            return true;
        }

        match next {
            NoChange => matches!(self, Observed | Selected),
            Superseded => matches!(
                self,
                Observed
                    | Selected
                    | Planned
                    | WorktreeReady
                    | Materializing
                    | PolicyValid
                    | QuickGated
                    | Repairing
            ),
            BlockedHuman | Quarantined | Failed => !self.is_terminal(),
            Rejected => matches!(
                self,
                PolicyValid | QuickGated | Repairing | CandidateAccepted
            ),
            Abandoned => !self.is_terminal(),
            _ => false,
        }
    }

    /// Reports whether no further transition may originate from this state.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::ReleaseHandoff
                | Self::NoChange
                | Self::Superseded
                | Self::Quarantined
                | Self::Rejected
                | Self::Abandoned
                | Self::Failed
        )
    }
}

/// Separately records what fresh upstream evidence proves.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiscoveryDecision {
    /// No acceptable newer candidate exists in the maintained stream.
    Current,
    /// At least one acceptable newer candidate exists.
    UpdateAvailable,
    /// Evidence is missing, stale, incomplete, or contradictory.
    Unknown,
    /// A supply-chain or identity conflict prevents selection.
    Quarantined,
}

/// Records the logical outcome of one planned validation gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GateOutcome {
    /// The gate ran and passed, or policy proved it inapplicable.
    Success,
    /// The gate ran and failed, or its policy input was invalid.
    Failure,
    /// The gate could not run or requires a human decision.
    ActionRequired,
    /// The run was superseded or deliberately stopped.
    Cancelled,
}

/// Identifies the actor class responsible for a durable decision or effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActorClass {
    /// The deterministic local controller performed the operation.
    Controller,
    /// The local maintainer explicitly authorized the operation.
    Maintainer,
    /// A bounded model proposed data through the mutation gateway.
    Agent,
    /// A remote system supplied an observed fact without local authority.
    RemoteObservation,
}

/// Binds a journal event to immutable objects available at that boundary.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EventBindings {
    /// Immutable campaign plan digest, when a plan exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<Sha256Digest>,
    /// Exact worktree tree digest, when materialization has begun.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree: Option<Sha256Digest>,
    /// Exact Git commit content digest, when a candidate commit exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<Sha256Digest>,
}

/// Carries one durable intent, result, transition, or decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum JournalPayload {
    /// Records intent before an external effect begins.
    EffectIntent {
        /// Digest of the closed typed effect request.
        request: Sha256Digest,
    },
    /// Records the observed result of a previously journaled effect.
    EffectResult {
        /// Sequence of the matching effect intent.
        intent_sequence: u64,
        /// Logical result classification.
        outcome: GateOutcome,
        /// Optional digest of retained bounded output.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        output: Option<Sha256Digest>,
    },
    /// Advances the durable run state through one legal edge.
    Transition {
        /// State before the transition.
        from: RunState,
        /// State after the transition.
        to: RunState,
    },
    /// Records a typed human or controller decision.
    Decision {
        /// Stable decision kind interpreted by the operation schema.
        decision: String,
        /// Digest of the exact reviewed decision input.
        subject: Sha256Digest,
    },
}

/// Contains one self-verifying record in the append-only run journal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct JournalEvent {
    /// Selects the exact closed journal-event schema.
    pub schema: String,
    /// Monotonic run-global sequence starting at one.
    pub journal_sequence: u64,
    /// Digest of the preceding record, absent only at sequence one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_record_digest: Option<Sha256Digest>,
    /// Digest of every field except this digest.
    pub record_digest: Sha256Digest,
    /// Durable run receiving the event.
    pub run_id: RunId,
    /// Reconstructible attempt number, when the event concerns an attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<u32>,
    /// Typed controller operation.
    pub operation: OperationId,
    /// Actor class responsible for the event.
    pub actor: ActorClass,
    /// Immutable object bindings available at this boundary.
    pub bindings: EventBindings,
    /// Durable event data.
    pub payload: JournalPayload,
    /// Wall-clock observation for explanation, never event ordering.
    pub observed_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JournalDigestInput<'a> {
    schema: &'a str,
    journal_sequence: u64,
    previous_record_digest: Option<Sha256Digest>,
    run_id: &'a RunId,
    attempt: Option<u32>,
    operation: &'a OperationId,
    actor: ActorClass,
    bindings: &'a EventBindings,
    payload: &'a JournalPayload,
    observed_at: &'a str,
}

impl JournalEvent {
    /// Computes the domain-separated digest committed by `record_digest`.
    ///
    /// # Errors
    ///
    /// Returns an error when the event cannot be encoded as canonical JSON.
    pub fn computed_digest(&self) -> Result<Sha256Digest> {
        let input = JournalDigestInput {
            schema: &self.schema,
            journal_sequence: self.journal_sequence,
            previous_record_digest: self.previous_record_digest,
            run_id: &self.run_id,
            attempt: self.attempt,
            operation: &self.operation,
            actor: self.actor,
            bindings: &self.bindings,
            payload: &self.payload,
            observed_at: &self.observed_at,
        };
        Sha256Digest::of_canonical(MAINTENANCE_JOURNAL_EVENT_V1, &input)
    }

    /// Verifies schema identity, digest integrity, and transition legality.
    ///
    /// # Errors
    ///
    /// Returns an error for an incompatible schema, invalid sequence, changed
    /// record fields, invalid timestamp shape, or illegal state transition.
    pub fn verify(&self) -> Result<()> {
        if self.schema != MAINTENANCE_JOURNAL_EVENT_V1 {
            bail!("unsupported maintenance journal schema: {}", self.schema);
        }
        if self.journal_sequence == 0 {
            bail!("journal sequence must start at one");
        }
        if self.observed_at.is_empty() || self.observed_at.len() > 64 {
            bail!("journal observation time is invalid");
        }
        if let JournalPayload::Transition { from, to } = self.payload
            && !from.can_transition_to(to)
        {
            bail!("illegal maintenance transition: {from:?} -> {to:?}");
        }
        if self.computed_digest()? != self.record_digest {
            bail!("maintenance journal record digest mismatch");
        }
        Ok(())
    }
}

/// Verifies a complete in-memory journal prefix and returns its durable state.
///
/// # Errors
///
/// Returns an error for an empty journal, a corrupt record, a gap, a broken
/// digest link, a run mismatch, or a transition whose `from` state disagrees
/// with the reduced state.
pub fn verify_journal(events: &[JournalEvent]) -> Result<RunState> {
    let Some(first) = events.first() else {
        bail!("maintenance journal must contain at least one event");
    };
    let run_id = &first.run_id;
    let mut previous = None;
    let mut state = None;

    for (index, event) in events.iter().enumerate() {
        event.verify()?;
        let expected_sequence = u64::try_from(index)
            .map_err(|error| anyhow::anyhow!("journal index overflow: {error}"))?
            + 1;
        if event.journal_sequence != expected_sequence {
            bail!("maintenance journal sequence gap at {expected_sequence}");
        }
        if &event.run_id != run_id {
            bail!("maintenance journal contains more than one run");
        }
        if event.previous_record_digest != previous {
            bail!("maintenance journal digest chain is broken at {expected_sequence}");
        }
        if let JournalPayload::Transition { from, to } = event.payload {
            if state.is_none() && from != RunState::Observed {
                bail!("first transition must originate at observed");
            }
            if state.is_some_and(|current| current != from) {
                bail!("transition source disagrees with reduced run state");
            }
            state = Some(to);
        }
        previous = Some(event.record_digest);
    }

    state.ok_or_else(|| anyhow::anyhow!("maintenance journal has no state transition"))
}

/// Carries bounded invocation-local progress that never enters durable state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProgressEvent {
    /// Selects the exact closed progress-event schema.
    pub schema: String,
    /// Monotonic sequence scoped to one process invocation.
    pub stream_sequence: u64,
    /// Operation producing progress.
    pub operation: OperationId,
    /// Optional durable run associated with the operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<RunId>,
    /// Current task status.
    pub status: TaskStatus,
    /// Human-readable bounded message interpreted only as display text.
    pub message: String,
    /// Completed work units when a meaningful counter exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed: Option<u64>,
    /// Total work units when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    /// Elapsed duration in integer milliseconds.
    pub elapsed_ms: u64,
}

impl ProgressEvent {
    /// Validates progress schema and bounded counter semantics.
    ///
    /// # Errors
    ///
    /// Returns an error for incompatible schema, zero sequence, oversized
    /// display text, or completed work exceeding a declared total.
    pub fn validate(&self) -> Result<()> {
        if self.schema != MAINTENANCE_PROGRESS_EVENT_V1 {
            bail!("unsupported maintenance progress schema: {}", self.schema);
        }
        if self.stream_sequence == 0 {
            bail!("progress stream sequence must start at one");
        }
        if self.message.len() > 4096 {
            bail!("progress message exceeds 4096 bytes");
        }
        if let (Some(completed), Some(total)) = (self.completed, self.total)
            && completed > total
        {
            bail!("progress completed count exceeds total");
        }
        Ok(())
    }
}

/// Describes ephemeral execution status in a controller-owned task DAG.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaskStatus {
    /// The operation has not begun.
    Pending,
    /// The operation is active.
    Running,
    /// The operation reached its typed result boundary.
    Completed,
}

#[cfg(test)]
mod tests {
    use aos_contract::canonical;

    use super::*;

    fn transition(
        sequence: u64,
        previous: Option<Sha256Digest>,
        from: RunState,
        to: RunState,
    ) -> Result<JournalEvent> {
        let mut event = JournalEvent {
            schema: MAINTENANCE_JOURNAL_EVENT_V1.to_string(),
            journal_sequence: sequence,
            previous_record_digest: previous,
            record_digest: Sha256Digest::of_bytes([]),
            run_id: RunId::parse("01K4D9HMR09Q6S37FX9PWGCM8A")?,
            attempt: None,
            operation: OperationId::parse("state-transition")?,
            actor: ActorClass::Controller,
            bindings: EventBindings::default(),
            payload: JournalPayload::Transition { from, to },
            observed_at: "2026-09-03T12:00:00Z".to_string(),
        };
        event.record_digest = event.computed_digest()?;
        Ok(event)
    }

    #[test]
    fn normal_and_repair_transitions_are_explicit() {
        assert!(RunState::Observed.can_transition_to(RunState::Selected));
        assert!(RunState::QuickGated.can_transition_to(RunState::Repairing));
        assert!(RunState::Repairing.can_transition_to(RunState::PolicyValid));
        assert!(!RunState::Planned.can_transition_to(RunState::FinalGated));
        assert!(!RunState::NoChange.can_transition_to(RunState::Selected));
    }

    #[test]
    fn journal_chain_reduces_only_verified_transitions() -> Result<()> {
        let first = transition(1, None, RunState::Observed, RunState::Selected)?;
        let second = transition(
            2,
            Some(first.record_digest),
            RunState::Selected,
            RunState::Planned,
        )?;
        assert_eq!(verify_journal(&[first, second])?, RunState::Planned);
        Ok(())
    }

    #[test]
    fn journal_rejects_tampering_gaps_and_skips() -> Result<()> {
        let first = transition(1, None, RunState::Observed, RunState::Selected)?;
        let mut tampered = first.clone();
        tampered.observed_at = "2026-09-03T12:00:01Z".to_string();
        assert!(verify_journal(&[tampered]).is_err());

        let gap = transition(
            3,
            Some(first.record_digest),
            RunState::Selected,
            RunState::Planned,
        )?;
        assert!(verify_journal(&[first.clone(), gap]).is_err());

        let skipped = transition(1, None, RunState::Observed, RunState::FinalGated)?;
        assert!(verify_journal(&[skipped]).is_err());
        Ok(())
    }

    #[test]
    fn progress_is_bounded_and_not_a_journal_record() -> Result<()> {
        let event = ProgressEvent {
            schema: MAINTENANCE_PROGRESS_EVENT_V1.to_string(),
            stream_sequence: 1,
            operation: OperationId::parse("download")?,
            run_id: None,
            status: TaskStatus::Running,
            message: "fetching source".to_string(),
            completed: Some(4),
            total: Some(3),
            elapsed_ms: 10,
        };
        assert!(event.validate().is_err());
        assert!(canonical::to_vec(&event).is_ok());
        Ok(())
    }
}
