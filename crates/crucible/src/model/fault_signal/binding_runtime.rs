//! Runtime evaluation of signal-to-effect bindings.
//!
//! This module is the sole bridge from the deterministic signal evaluator to
//! production adapter actions. It owns mapping state, selector membership,
//! keyed hazard choices, persistent contributor installation, and causal
//! observations. Adapters never evaluate signal graphs or reinterpret mapping
//! schemas themselves.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::*;

mod error;
mod mapping_codec;
mod replay;
mod transaction;

pub use error::BindingRuntimeError;
use mapping_codec::{mapped_values_digest, resolved_mapping_output_digest};
use replay::{resolved_replay_work_item, verify_replay_results};
use transaction::prepare_and_commit;

/// One mutation requested of the owning production adapter.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum BindingActionKind {
    /// Installs or replaces one persistent contribution.
    UpsertPersistent,
    /// Removes one persistent contribution.
    RemovePersistent,
    /// Applies one opportunity, impulse, or state-machine effect.
    Apply,
}

/// Canonical identity of the transition that produced an adapter action.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum BindingActionCause {
    /// A scheduled signal mapping transition.
    Signal,
    /// One exact adapter opportunity and its immutable typed identity fields.
    Opportunity {
        /// Canonical opportunity identity.
        identity: ContentHash,
        /// Adapter-visible opportunity payload used for exact hardware matching.
        payload: OpportunityPayload,
    },
    /// One exact dynamic-path membership transition.
    DynamicMembership {
        /// Authored path identity.
        path: FaultObjectId,
        /// Path-owned transition sequence.
        sequence: u64,
        /// Route/association evidence.
        evidence: ContentHash,
    },
}

/// Fully resolved adapter input produced by one binding evaluation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedBindingAction {
    /// Requested adapter mutation.
    pub kind: BindingActionKind,
    /// Binding that caused the action.
    pub binding: FaultObjectId,
    /// Concrete target resolved before execution.
    pub target: ResolvedFaultTarget,
    /// Exact adapter phase.
    pub phase: FaultPhase,
    /// Validated typed effect template.
    pub effect: Arc<EffectRequest>,
    /// Closed typed mapping output consumed without adapter reinterpretation.
    pub mapping_output: Arc<ResolvedMappingOutput>,
    /// Canonical digest of the mapped value vector.
    pub mapped_digest: ContentHash,
    /// Binding transition sequence after this decision.
    pub transition_sequence: u64,
    /// Matching opportunity identity for opportunity-scoped actions.
    pub opportunity: Option<ContentHash>,
    /// Exact scheduler coordinate.
    pub coordinate: FaultCoordinate,
    /// Exact transition identity that caused this action.
    pub cause: BindingActionCause,
    /// Locked-replay before-state digest that the live backend must verify.
    pub expected_precondition: Option<ContentHash>,
}

impl ResolvedBindingAction {
    /// Returns the canonical identity used to match an adapter result.
    #[must_use]
    pub fn id(&self) -> ContentHash {
        self.identity_with_precondition(self.expected_precondition)
    }

    /// Returns the canonical identity of the applied adapter state.
    ///
    /// The locked-replay precondition authorizes an application but is not
    /// part of the state installed by that application. Host adapters use this
    /// identity for their visible-state digest so an otherwise identical
    /// locked replay produces the same evidence as the recorded execution.
    #[must_use]
    pub fn committed_state_id(&self) -> ContentHash {
        self.identity_with_precondition(None)
    }

    fn identity_with_precondition(
        &self,
        expected_precondition: Option<ContentHash>,
    ) -> ContentHash {
        let kind = match self.kind {
            BindingActionKind::UpsertPersistent => "upsert_persistent",
            BindingActionKind::RemovePersistent => "remove_persistent",
            BindingActionKind::Apply => "apply",
        };
        let cause = match &self.cause {
            BindingActionCause::Signal => String::from("signal"),
            BindingActionCause::Opportunity { identity, .. } => {
                format!("opportunity:{}", identity.to_hex())
            }
            BindingActionCause::DynamicMembership {
                path,
                sequence,
                evidence,
            } => format!(
                "dynamic_membership:{}:{sequence}:{}",
                path.as_str(),
                evidence.to_hex()
            ),
        };
        let retired = self
            .coordinate
            .retired_instructions
            .map_or_else(|| String::from("none"), |value| value.to_string());
        let mut material = format!(
            "kind={kind};binding={};phase={};effect={};mapped={};transition={};opportunity={};virtual_nanos={};retired={retired};cause={cause};precondition={};target=",
            self.binding.as_str(),
            self.phase.as_str(),
            self.effect.kind().as_str(),
            self.mapped_digest.to_hex(),
            self.transition_sequence,
            self.opportunity
                .map_or_else(|| String::from("none"), |value| value.to_hex()),
            self.coordinate.virtual_nanos,
            expected_precondition.map_or_else(|| String::from("none"), |value| value.to_hex()),
        );
        self.target.append_canonical(&mut material);
        ContentHash::from_canonical_material("crucible.resolved-binding-action.v1", &material)
    }
}

/// One production-adapter preparation result corresponding to one action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedActionResult {
    /// Exact prepared action identity.
    pub action: ContentHash,
    /// Backend-observed state digest immediately before application.
    pub precondition: Option<ContentHash>,
    /// Adapter-owned successful application evidence.
    pub observation: FaultObservation,
}

/// One prepared or committed atomic action batch.
///
/// `prepare_batch` returns the transaction with prediction-only results;
/// callers must not retain those results as application evidence. A successful
/// `commit_batch` returns the same transaction with backend-observed results.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PreparedActionBatch {
    /// Adapter-owned opaque transaction identity used for the commit.
    pub transaction: ContentHash,
    /// Predicted results in exact action order, one per action.
    pub results: Vec<PreparedActionResult>,
}

/// Prepared adapter actions and pre-application observations from one boundary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BindingEvaluation {
    /// Adapter actions in canonical binding/target/phase order.
    pub actions: Vec<ResolvedBindingAction>,
    /// Causal observations in their production order.
    pub observations: Vec<FaultObservation>,
    /// Policy-retained canonical sample payloads.
    pub retained_samples: Vec<RetainedBindingSample>,
    /// Finite search decisions reached at this boundary.
    pub search_choices: Vec<BindingSearchChoice>,
    /// Earliest exact virtual-time boundary the scheduler must enqueue.
    pub next_wakeup_nanos: Option<u64>,
    /// Referenced exported event signals emitted at this boundary.
    pub emitted_events: Vec<ReferencedSignalEvent>,
    /// State-machine transition events emitted at this boundary.
    pub state_machine_events: Vec<StatefulSignalEvent>,
}

/// One emitted event explicitly referenced by an admitted effect contract.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReferencedSignalEvent {
    /// Exported event signal identity.
    pub signal: SignalId,
    /// Exact scheduler coordinate at which it was observed.
    pub coordinate: FaultCoordinate,
    /// Stable order among evaluations at the same coordinate.
    pub same_coordinate_sequence: u64,
    /// Complete typed event value.
    pub value: SignalValue,
    /// Canonical digest of the typed event value.
    pub evidence: ContentHash,
}

impl ReferencedSignalEvent {
    /// Returns the canonical identity and encoded size of the typed event value.
    ///
    /// # Errors
    ///
    /// Returns [`BindingRuntimeError::Trace`] if the value cannot be encoded in
    /// the canonical signal trace representation.
    pub fn canonical_value_identity(&self) -> Result<(ContentHash, usize), BindingRuntimeError> {
        let bytes = encode_signal_value(&self.value).map_err(BindingRuntimeError::Trace)?;
        Ok((ContentHash::from_bytes(&bytes), bytes.len()))
    }
}

/// One sample payload retained under a binding's observability policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedBindingSample {
    /// Binding that sampled the values.
    pub binding: FaultObjectId,
    /// Exact scheduler coordinate.
    pub coordinate: FaultCoordinate,
    /// Opportunity identity for opportunity-scoped samples.
    pub opportunity: Option<ContentHash>,
    /// Canonical sampled values, or `None` for explicit inactivity.
    pub values: Option<Vec<SignalValue>>,
    /// Sample identity retained by the observation record.
    pub evidence: ContentHash,
}

impl BindingRuntimeCheckpoint {
    /// Validates the complete bridge continuation against independent identity.
    ///
    /// # Errors
    ///
    /// Returns [`BindingRuntimeError`] for any identity, bound, or mutable-state
    /// inconsistency.
    pub fn validate(
        &self,
        program: &SignalProgram,
        bindings: &[FaultBinding],
        scenario_seed: ContentHash,
        resource_limits: FaultResourceLimits,
    ) -> Result<(), BindingRuntimeError> {
        let mut bindings = bindings.to_vec();
        bindings.sort_by(|left, right| left.id().cmp(right.id()));
        validate_binding_checkpoint(program, &bindings, scenario_seed, resource_limits, self)
    }
}

/// Two-phase production-adapter boundary for one fully resolved action batch.
pub trait FaultActionSink {
    /// Validates and prepares every action without changing visible state.
    ///
    /// Returned observations are predictions used only to prove complete action
    /// ordering. Actual application evidence is returned by `commit_batch`.
    ///
    /// # Errors
    ///
    /// Returns [`RejectedActionBatch`] when validation or application fails.
    /// The sink must roll back the entire batch before returning an error.
    fn prepare_batch(
        &mut self,
        actions: &[ResolvedBindingAction],
    ) -> Result<PreparedActionBatch, Box<RejectedActionBatch>>;

    /// Discards one prepared transaction without changing visible state.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when the adapter cannot prove that all
    /// staged resources and mutations were discarded. The runtime becomes
    /// terminally poisoned after this error.
    fn abort_batch(&mut self, transaction: ContentHash) -> Result<(), FaultRuntimeError>;

    /// Atomically commits one previously prepared transaction and returns actual evidence.
    ///
    /// # Errors
    ///
    /// Returns [`FaultActionCommitError::Rejected`] only when adapter-visible
    /// state remains unchanged. Returns [`FaultActionCommitError::Fatal`] when
    /// the backend cannot prove whether a destructive commit became visible;
    /// the owning runtime must become terminally poisoned.
    fn commit_batch(
        &mut self,
        transaction: ContentHash,
    ) -> Result<PreparedActionBatch, FaultActionCommitError>;
}

/// Failure class for an atomic adapter commit.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FaultActionCommitError {
    /// The entire batch was rejected before any visible state changed.
    #[error("fault action commit was rejected: {0:?}")]
    Rejected(Box<RejectedActionBatch>),
    /// Visibility is ambiguous or partial and the run cannot safely continue.
    #[error("fault action commit became fatal: {0}")]
    Fatal(FaultRuntimeError),
}

/// Atomic adapter rejection with durable failure evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejectedActionBatch {
    /// Typed production-adapter failure.
    pub error: FaultRuntimeError,
    /// Adapter-owned `EffectRejected` observations with before-state evidence.
    pub observations: Vec<FaultObservation>,
    /// Exact action whose validation/application rejected, when applicable.
    pub rejected_action: Option<ContentHash>,
}

/// Mutable deterministic runtime for one validated program and binding set.
pub struct FaultBindingRuntime<'a> {
    program: &'a SignalProgram,
    bindings: Vec<FaultBinding>,
    evaluator: SignalEvaluator<'a>,
    artifacts: &'a dyn SignalArtifactProvider,
    scenario_seed: ContentHash,
    resource_limits: FaultResourceLimits,
    states: BTreeMap<FaultObjectId, BindingRuntimeState>,
    active: ActiveContributionTable,
    dynamic_membership: BTreeMap<FaultObjectId, DynamicMembershipState>,
    consumed_opportunities: BTreeMap<ConsumedOpportunityKey, ConsumedOpportunityState>,
    search_overrides: BTreeMap<SearchChoiceId, SearchOverride>,
    consumed_search_overrides: std::collections::BTreeSet<SearchChoiceId>,
    scheduler_cursor: Option<FaultSchedulerCursor>,
    boundary_completed_cursor: Option<FaultSchedulerCursor>,
    poisoned: bool,
}

#[path = "binding_runtime/application.rs"]
mod application;
#[path = "binding_runtime/construction.rs"]
mod construction;
#[path = "binding_runtime/evaluation.rs"]
mod evaluation;
#[path = "binding_runtime/runtime_api.rs"]
mod runtime_api;

#[path = "binding_runtime/search_helpers.rs"]
mod search_helpers;
use search_helpers::*;
#[path = "binding_runtime/scheduling_helpers.rs"]
mod scheduling_helpers;
use scheduling_helpers::*;
#[path = "binding_runtime/mapping_helpers.rs"]
mod mapping_helpers;
use mapping_helpers::*;
#[path = "binding_runtime/checkpoint_validation.rs"]
mod checkpoint_validation;
use checkpoint_validation::*;

#[cfg(test)]
#[path = "binding_runtime_test.rs"]
mod tests;
