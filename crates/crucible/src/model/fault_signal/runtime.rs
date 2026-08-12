//! Deterministic binding, composition, checkpoint, search, and replay state.
//!
//! The types in this module are the mutable spine shared by production
//! adapters. Every state item that can affect a later opportunity is bounded,
//! ordered, content-addressed, and represented in [`FaultRuntimeCheckpoint`].

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use super::*;

/// Semantic version of runtime/checkpoint state.
pub const FAULT_RUNTIME_STATE_VERSION: u16 = 2;

/// Mutable activation state for one binding.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct BindingRuntimeState {
    /// Whether a persistent contribution is currently active.
    pub active: bool,
    /// Monotone transition sequence used in keyed decisions and replay.
    pub transition_sequence: u64,
    /// Candidate activation value during threshold residence.
    pub pending_activation: Option<bool>,
    /// Coordinate at which the pending value began residing.
    pub pending_since_nanos: Option<u64>,
    /// Last mapped parameter digest.
    pub mapped_parameters: Option<ContentHash>,
    /// Last mapped values required for later dynamic membership changes.
    pub mapped_values: Vec<SignalValue>,
    /// Last typed mapping result required for adapter reconciliation.
    pub mapping_output: Option<ResolvedMappingOutput>,
    /// Last sample identity, including event coordinates where applicable.
    pub last_sample_identity: Option<ContentHash>,
    /// Last event identity consumed by an impulse mapping.
    pub last_event_identity: Option<ContentHash>,
    /// Last virtual coordinate at which this binding sampled its inputs.
    pub last_sample_nanos: Option<u64>,
    /// Total admitted samples, including explicit inactive results.
    pub sample_count: u64,
    /// Consecutive samples with the same canonical identity.
    pub unchanged_sample_count: u64,
    /// Number of finite runtime search choices emitted by this binding.
    pub search_choice_count: u64,
}

/// Stable scope for monotone adapter opportunity delivery.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct ConsumedOpportunityKey {
    /// Binding consuming the adapter opportunities.
    pub binding: FaultObjectId,
    /// Concrete adapter target.
    pub target: ResolvedFaultTarget,
    /// Exact adapter phase.
    pub phase: FaultPhase,
    /// Adapter operation sequence domain.
    pub operation: FaultOperation,
}

/// Last accepted opportunity identity in one stable scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ConsumedOpportunityState {
    /// Monotone adapter-owned sequence.
    pub sequence: u64,
    /// Full immutable opportunity identity at that sequence.
    pub identity: ContentHash,
    /// Exact scheduler coordinate at which the opportunity was consumed.
    pub coordinate: FaultCoordinate,
    /// Stable work sequence at that scheduler coordinate.
    pub same_coordinate_sequence: u64,
}

/// Last committed global scheduler boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct FaultSchedulerCursor {
    /// Global virtual time in nanoseconds.
    pub virtual_nanos: u64,
    /// Stable sequence among scheduler work at the same virtual time.
    pub same_coordinate_sequence: u64,
}

/// Canonical dynamic-path membership transition supplied by network state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DynamicMembershipTransition {
    /// Authored dynamic path identity.
    pub path: FaultObjectId,
    /// Exact membership state-machine semantic version.
    pub semantic_version: u16,
    /// Next monotone path-owned transition sequence.
    pub sequence: u64,
    /// Content-addressed route/association evidence.
    pub evidence: ContentHash,
    /// New canonical resolved link membership.
    pub targets: ResolvedTargetSet,
}

/// Last accepted state of one dynamic selector.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct DynamicMembershipState {
    /// Authored dynamic path identity.
    pub path: FaultObjectId,
    /// Exact membership state-machine semantic version.
    pub semantic_version: u16,
    /// Last accepted transition sequence.
    pub sequence: u64,
    /// Evidence for the current membership.
    pub evidence: ContentHash,
    /// Current canonical resolved link membership.
    pub targets: ResolvedTargetSet,
}

/// Complete mutable state owned by [`FaultBindingRuntime`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct BindingRuntimeCheckpoint {
    /// Exact runtime codec semantic version.
    pub semantic_version: u16,
    /// Exact signal-program identity.
    pub signal_program: ContentHash,
    /// Scenario-wide deterministic seed.
    pub scenario_seed: ContentHash,
    /// Exact scenario-owned resource contract used by this continuation.
    pub resource_limits: FaultResourceLimits,
    /// Complete canonical evaluator continuation.
    pub evaluator: SignalEvaluatorCheckpoint,
    /// Complete per-binding state.
    pub bindings: BTreeMap<FaultObjectId, BindingRuntimeState>,
    /// Exact admitted binding and named-declaration contracts.
    pub binding_contracts: Vec<FaultBinding>,
    /// Active persistent contributions.
    pub active: ActiveContributionTable,
    /// Current dynamic selector membership.
    pub dynamic_membership: BTreeMap<FaultObjectId, DynamicMembershipState>,
    /// Last accepted opportunity in every consumed scope.
    pub consumed_opportunities: BTreeMap<ConsumedOpportunityKey, ConsumedOpportunityState>,
    /// Concrete finite explorer overrides available to this continuation.
    pub search_overrides: BTreeMap<SearchChoiceId, SearchOverride>,
    /// One-shot override identities already consumed by execution.
    pub consumed_search_overrides: BTreeSet<SearchChoiceId>,
    /// Last committed scheduler boundary.
    pub scheduler_cursor: Option<FaultSchedulerCursor>,
    /// Last scheduler cursor whose non-opportunity bindings completed.
    pub boundary_completed_cursor: Option<FaultSchedulerCursor>,
}

/// One finite search decision exposed by binding evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingSearchChoice {
    /// Stable decision identity.
    pub id: SearchChoiceId,
    /// Exact candidate-set identity.
    pub candidates_digest: ContentHash,
    /// Number of finite candidates.
    pub candidate_count: u32,
    /// Chosen zero-based candidate index, or `None` for the unmodified model result.
    pub selected_index: Option<u32>,
    /// Whether a replay/explorer override selected the result.
    pub overridden: bool,
}

impl BindingRuntimeState {
    /// Advances the transition sequence and installs a new active state.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError::SequenceOverflow`] if the transition
    /// sequence is exhausted.
    pub fn transition(&mut self, active: bool) -> Result<u64, FaultRuntimeError> {
        self.transition_sequence = self
            .transition_sequence
            .checked_add(1)
            .ok_or(FaultRuntimeError::SequenceOverflow("binding_transition"))?;
        self.active = active;
        self.pending_activation = None;
        self.pending_since_nanos = None;
        Ok(self.transition_sequence)
    }
}

/// Stable key for one active persistent contribution.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct ActiveContributionKey {
    /// Concrete adapter target.
    pub target: ResolvedFaultTarget,
    /// Application phase.
    pub phase: FaultPhase,
    /// Closed effect family.
    pub effect: EffectKind,
    /// Binding tie-breaker and healing identity.
    pub binding: FaultObjectId,
}

/// One active typed effect contribution.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ActiveEffectContribution {
    /// Typed validated request.
    pub request: Arc<EffectRequest>,
    /// Digest of canonical parameters after mapping.
    pub mapped_parameters: ContentHash,
    /// Closed typed mapping result consumed by the adapter.
    pub mapping_output: Arc<ResolvedMappingOutput>,
    /// Binding transition sequence which installed this contribution.
    pub transition_sequence: u64,
}

/// Canonical active-contribution table.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct ActiveContributionTable {
    entries: BTreeMap<ActiveContributionKey, ActiveEffectContribution>,
}

impl ActiveContributionTable {
    /// Installs or replaces exactly one binding's persistent contribution.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when the request is not persistent, its
    /// target or phase is illegal, or the table hard limit would be exceeded.
    pub fn activate(
        &mut self,
        key: ActiveContributionKey,
        contribution: ActiveEffectContribution,
        resource_limits: FaultResourceLimits,
    ) -> Result<Option<ActiveEffectContribution>, FaultRuntimeError> {
        if contribution.request.lifetime() != EffectLifetime::Persistent {
            return Err(FaultRuntimeError::NonPersistentActivation);
        }
        validate_contribution_key(&key, contribution.request.kind())?;
        if !self.entries.contains_key(&key) {
            let current = u64::try_from(
                self.entries
                    .keys()
                    .filter(|entry| entry.target == key.target)
                    .count(),
            )
            .map_err(|_| FaultRuntimeError::CountOverflow("active_contributions_per_target"))?;
            resource_limits
                .reserve("active_contributions_per_target", current, 1)
                .map_err(FaultRuntimeError::ResourceLimit)?;
        }
        Ok(self.entries.insert(key, contribution))
    }

    /// Removes only one named binding contribution from one effect group.
    #[must_use]
    pub fn deactivate(&mut self, key: &ActiveContributionKey) -> Option<ActiveEffectContribution> {
        self.entries.remove(key)
    }

    /// Returns entries in canonical target/phase/effect/binding order.
    #[must_use]
    pub const fn entries(&self) -> &BTreeMap<ActiveContributionKey, ActiveEffectContribution> {
        &self.entries
    }

    /// Builds canonical composition groups for production adapters.
    #[must_use]
    pub fn composition_groups(&self) -> Vec<EffectComposition> {
        let mut groups: Vec<EffectComposition> = Vec::new();
        for (key, contribution) in &self.entries {
            let same_group = groups.last_mut().filter(|group| {
                group.target == key.target && group.phase == key.phase && group.effect == key.effect
            });
            if let Some(group) = same_group {
                group.contributors.push(CompositionContributor {
                    binding: key.binding.clone(),
                    parameters: contribution.mapped_parameters,
                    mapping_output: (*contribution.mapping_output).clone(),
                });
                group.recompute_digest();
            } else {
                groups.push(EffectComposition::new(
                    key.target.clone(),
                    key.phase,
                    key.effect,
                    CompositionContributor {
                        binding: key.binding.clone(),
                        parameters: contribution.mapped_parameters,
                        mapping_output: (*contribution.mapping_output).clone(),
                    },
                ));
            }
        }
        groups
    }
}

fn validate_contribution_key(
    key: &ActiveContributionKey,
    effect: EffectKind,
) -> Result<(), FaultRuntimeError> {
    key.target.validate().map_err(FaultRuntimeError::Contract)?;
    let descriptor = effect.descriptor();
    if key.effect != effect
        || !descriptor.targets.contains(&key.target.kind())
        || !descriptor.phases.contains(&key.phase)
    {
        return Err(FaultRuntimeError::InvalidContributionKey);
    }
    Ok(())
}

/// One ordered input to a registered composition algebra.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompositionContributor {
    /// Stable binding identity.
    pub binding: FaultObjectId,
    /// Canonical mapped-parameter digest.
    pub parameters: ContentHash,
    /// Closed typed mapping result consumed by the registered algebra.
    pub mapping_output: ResolvedMappingOutput,
}

/// Canonical group passed to the owning production adapter for composition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectComposition {
    /// Concrete target shared by every contributor.
    pub target: ResolvedFaultTarget,
    /// Application phase shared by every contributor.
    pub phase: FaultPhase,
    /// Effect family shared by every contributor.
    pub effect: EffectKind,
    /// Registry-selected algebra.
    pub algebra: CompositionAlgebra,
    /// Contributors in stable binding-ID order.
    pub contributors: Vec<CompositionContributor>,
    /// Content identity of group membership and mapped parameters.
    pub digest: ContentHash,
}

impl EffectComposition {
    fn new(
        target: ResolvedFaultTarget,
        phase: FaultPhase,
        effect: EffectKind,
        contributor: CompositionContributor,
    ) -> Self {
        let mut value = Self {
            target,
            phase,
            effect,
            algebra: effect.descriptor().composition,
            contributors: vec![contributor],
            digest: ContentHash::default(),
        };
        value.recompute_digest();
        value
    }

    fn recompute_digest(&mut self) {
        let mut material = format!(
            "effect={};phase={};target=",
            self.effect.as_str(),
            self.phase.as_str()
        );
        self.target.append_canonical(&mut material);
        for contributor in &self.contributors {
            material.push_str(contributor.binding.as_str());
            material.push('=');
            material.push_str(&contributor.parameters.to_hex());
            material.push(';');
        }
        self.digest =
            ContentHash::from_canonical_material("crucible.effect-composition.v1", &material);
    }
}

/// Fine-grained live backend capability manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultCapabilityManifest {
    /// Backend implementation identity and version.
    pub backend: FaultObjectId,
    /// Exact supported capability IDs.
    pub capabilities: BTreeSet<FaultCapabilityId>,
    /// Canonical implementation-owned bound table.
    pub bounds: BTreeMap<FaultObjectId, u64>,
}

impl FaultCapabilityManifest {
    /// Verifies every binding against the live backend handshake.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError::MissingCapability`] at the first absent
    /// exact semantic capability.
    pub fn admit(&self, bindings: &[FaultBinding]) -> Result<(), FaultRuntimeError> {
        for binding in bindings {
            let capability = FaultCapabilityId::parse(binding.effect().capability())
                .map_err(FaultRuntimeError::Contract)?;
            if !self.capabilities.contains(&capability) {
                return Err(FaultRuntimeError::MissingCapability(capability));
            }
        }
        Ok(())
    }
}

/// Identity of one finite search decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct SearchChoiceId(ContentHash);

impl SearchChoiceId {
    /// Builds the decision-domain-separated identity required for replay.
    #[must_use]
    pub fn new(
        program: ContentHash,
        binding: &FaultObjectId,
        opportunity: Option<ContentHash>,
        sample: ContentHash,
        candidates: ContentHash,
    ) -> Self {
        let material = format!(
            "program={};binding={};opportunity={};sample={};candidates={};",
            program.to_hex(),
            binding.as_str(),
            opportunity.map_or_else(|| String::from("none"), |value| value.to_hex()),
            sample.to_hex(),
            candidates.to_hex()
        );
        Self(ContentHash::from_canonical_material(
            "crucible.search-choice.v1",
            &material,
        ))
    }

    /// Returns the underlying content identity.
    #[must_use]
    pub const fn content_hash(self) -> ContentHash {
        self.0
    }
}

/// Concrete explorer result retained for ordinary locked replay.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SearchOverride {
    /// Chosen zero-based candidate index.
    pub candidate_index: u32,
    /// Digest of the exact finite candidate set.
    pub candidates_digest: ContentHash,
    /// Parent branch, if this choice forked an earlier search branch.
    pub parent_branch: Option<ContentHash>,
}

/// Authoritative replay behavior.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(tag = "mode", content = "alignment", rename_all = "snake_case")]
pub enum FaultReplayMode {
    /// Reevaluates causes and verifies every resolved record.
    RecomputedCause,
    /// Uses exact resolved effects after strict context verification.
    LockedEffect,
    /// Uses an exact or explicitly bucketed network outcome stream.
    OutcomeOnlyNetwork(NetworkOutcomeAlignment),
}

/// Deterministic alignment contract for captured network frame outcomes.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum NetworkOutcomeAlignment {
    /// Matches immutable producer, destination, ancestry, sequence, and bytes.
    ExactFrameKey,
    /// Matches the producer-owned sequence independently for each direction.
    ProducerDirectionSequence,
    /// Matches the exact scheduler coordinate and same-coordinate sequence.
    ExactEventCoordinate,
    /// Matches ordered compatible frames within the same positive time bucket.
    OrderedTimeBucket {
        /// Width of one alignment bucket in virtual nanoseconds.
        width_nanos: u64,
    },
}

/// One scheduler work item and every resolved effect committed for it.
///
/// Empty `records` is meaningful: it proves that the observed boundary or
/// opportunity passed without an adapter mutation while still authenticating
/// the complete post-derivation continuation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedReplayWorkItem {
    /// Scheduler coordinate at which the work item was evaluated.
    pub coordinate: FaultCoordinate,
    /// Stable order among scheduler work at the same coordinate.
    pub same_coordinate_sequence: u64,
    /// Exact opportunity identity, or `None` for a scheduler boundary.
    pub opportunity: Option<ContentHash>,
    /// Concrete opportunity target, when present.
    pub target: Option<ResolvedFaultTarget>,
    /// Exact adapter operation, when present.
    pub operation: Option<FaultOperation>,
    /// Exact directional context, when present.
    pub direction: Option<FaultDirection>,
    /// Exact adapter application phase, when present.
    pub phase: Option<FaultPhase>,
    /// Coordinate-independent immutable network-frame identity.
    pub network_frame_key: Option<ContentHash>,
    /// Stable producer/direction/sequence network alignment identity.
    pub network_producer_direction_key: Option<ContentHash>,
    /// Complete post-derivation signal and binding continuation fingerprint.
    pub derivation_fingerprint: ContentHash,
    /// Ordered effects committed for this work item; an empty list records pass.
    pub records: Vec<ResolvedEffectRecord>,
}

impl ResolvedReplayWorkItem {
    pub(crate) fn new(
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
        opportunity: Option<&FaultOpportunity>,
        derivation_fingerprint: ContentHash,
        records: Vec<ResolvedEffectRecord>,
    ) -> Result<Self, FaultRuntimeError> {
        let item = Self {
            coordinate,
            same_coordinate_sequence,
            opportunity: opportunity.map(FaultOpportunity::id),
            target: opportunity.map(|value| value.target().clone()),
            operation: opportunity.map(FaultOpportunity::operation),
            direction: opportunity.and_then(FaultOpportunity::direction),
            phase: opportunity.map(FaultOpportunity::phase),
            network_frame_key: opportunity.and_then(FaultOpportunity::network_frame_key),
            network_producer_direction_key: opportunity
                .and_then(FaultOpportunity::network_producer_direction_key),
            derivation_fingerprint,
            records,
        };
        item.validate()?;
        Ok(item)
    }

    fn validate(&self) -> Result<(), FaultRuntimeError> {
        let opportunity_fields = [
            self.target.is_some(),
            self.operation.is_some(),
            self.phase.is_some(),
        ];
        if opportunity_fields
            .into_iter()
            .any(|present| present != self.opportunity.is_some())
            || self.network_frame_key.is_some() != self.network_producer_direction_key.is_some()
            || self.network_frame_key.is_some() && self.opportunity.is_none()
            || self.network_frame_key.is_some()
                && self
                    .operation
                    .is_none_or(|operation| operation.adapter() != FaultAdapter::Network)
        {
            return Err(FaultRuntimeError::InvalidReplayTrace);
        }
        for record in &self.records {
            record.validate().map_err(FaultRuntimeError::Contract)?;
            if record.coordinate != self.coordinate
                || record.same_coordinate_sequence != self.same_coordinate_sequence
                || record.opportunity != self.opportunity
                || record.derivation_fingerprint != self.derivation_fingerprint
                || self.target.as_ref() != Some(&record.target) && self.opportunity.is_some()
                || record.operation != self.operation
                || record.direction != self.direction
                || self.phase.is_some_and(|phase| phase != record.phase)
                || record.network_frame_key != self.network_frame_key
                || record.network_producer_direction_key != self.network_producer_direction_key
            {
                return Err(FaultRuntimeError::InvalidReplayTrace);
            }
        }
        Ok(())
    }
}

/// Ordered replay work-item trace and its next-item cursor.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedEffectTrace {
    /// Replay mode encoded in the reproduction artifact.
    pub mode: FaultReplayMode,
    /// Exact ordered boundaries and opportunities, including pass outcomes.
    pub work_items: Vec<ResolvedReplayWorkItem>,
    /// Next work item to consume.
    pub cursor: usize,
}

impl ResolvedEffectTrace {
    /// Encodes this trace as deterministic CBOR for artifact and RPC transport.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError::CheckpointEncoding`] when serialization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FaultRuntimeError> {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(self, &mut bytes)
            .map_err(|_| FaultRuntimeError::CheckpointEncoding)?;
        Ok(bytes)
    }

    /// Decodes and validates a deterministic CBOR trace.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when decoding fails or the trace violates
    /// the supplied scenario resource contract.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        resource_limits: FaultResourceLimits,
    ) -> Result<Self, FaultRuntimeError> {
        let trace: Self =
            ciborium::de::from_reader(bytes).map_err(|_| FaultRuntimeError::CheckpointEncoding)?;
        trace.validate(resource_limits)?;
        Ok(trace)
    }

    /// Validates trace bounds and every replay work item.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] for an oversized trace, invalid cursor,
    /// invalid work item, or non-network item in outcome-only network mode.
    pub fn validate(&self, resource_limits: FaultResourceLimits) -> Result<(), FaultRuntimeError> {
        if self.cursor > self.work_items.len() {
            return Err(FaultRuntimeError::InvalidReplayTrace);
        }
        let work_items = u64::try_from(self.work_items.len())
            .map_err(|_| FaultRuntimeError::CountOverflow("thin_replay_events"))?;
        resource_limits
            .reserve("thin_replay_events", 0, work_items)
            .map_err(FaultRuntimeError::ResourceLimit)?;
        let mut records = 0_u64;
        for item in &self.work_items {
            item.validate()?;
            let additional = u64::try_from(item.records.len())
                .map_err(|_| FaultRuntimeError::CountOverflow("resolved_effect_records"))?;
            records = records
                .checked_add(additional)
                .ok_or(FaultRuntimeError::CountOverflow("resolved_effect_records"))?;
            resource_limits
                .reserve("resolved_effect_records", 0, records)
                .map_err(FaultRuntimeError::ResourceLimit)?;
            if let FaultReplayMode::OutcomeOnlyNetwork(alignment) = self.mode {
                if item.network_frame_key.is_none()
                    || matches!(
                        alignment,
                        NetworkOutcomeAlignment::OrderedTimeBucket { width_nanos: 0 }
                    )
                    || item
                        .records
                        .iter()
                        .any(|record| record.effect.descriptor().adapter != FaultAdapter::Network)
                {
                    return Err(FaultRuntimeError::InvalidReplayTrace);
                }
            }
        }
        Ok(())
    }

    /// Returns the next work item after enforcing its selected alignment.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError::ReplayMismatch`] when the next recorded
    /// context does not align with the observed work item.
    pub fn work_item_for_context(
        &self,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
        opportunity: Option<&FaultOpportunity>,
    ) -> Result<Option<&ResolvedReplayWorkItem>, FaultRuntimeError> {
        if matches!(self.mode, FaultReplayMode::OutcomeOnlyNetwork(_))
            && opportunity
                .and_then(FaultOpportunity::network_frame_key)
                .is_none()
        {
            return Ok(None);
        }
        let Some(first) = self.work_items.get(self.cursor) else {
            return Err(FaultRuntimeError::ReplayExhausted);
        };
        let observed = opportunity.map(FaultOpportunity::id).unwrap_or_default();
        let matches = match self.mode {
            FaultReplayMode::RecomputedCause | FaultReplayMode::LockedEffect => {
                first.coordinate == coordinate
                    && first.same_coordinate_sequence == same_coordinate_sequence
                    && first.opportunity == opportunity.map(FaultOpportunity::id)
            }
            FaultReplayMode::OutcomeOnlyNetwork(alignment) => {
                let opportunity = opportunity.ok_or(FaultRuntimeError::InvalidReplayTrace)?;
                let compatible = first.target.as_ref() == Some(opportunity.target())
                    && first.operation == Some(opportunity.operation())
                    && first.phase == Some(opportunity.phase())
                    && first.direction == opportunity.direction();
                compatible
                    && match alignment {
                        NetworkOutcomeAlignment::ExactFrameKey => {
                            first.network_frame_key == opportunity.network_frame_key()
                        }
                        NetworkOutcomeAlignment::ProducerDirectionSequence => {
                            first.network_producer_direction_key
                                == opportunity.network_producer_direction_key()
                        }
                        NetworkOutcomeAlignment::ExactEventCoordinate => {
                            first.coordinate == coordinate
                                && first.same_coordinate_sequence == same_coordinate_sequence
                        }
                        NetworkOutcomeAlignment::OrderedTimeBucket { width_nanos } => {
                            width_nanos != 0
                                && first.coordinate.virtual_nanos / width_nanos
                                    == coordinate.virtual_nanos / width_nanos
                        }
                    }
            }
        };
        if !matches {
            return Err(FaultRuntimeError::ReplayMismatch {
                index: self.cursor,
                expected: first.opportunity,
                observed,
            });
        }
        Ok(Some(first))
    }

    /// Advances after one fully verified work item.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError::ReplayExhausted`] at the end of the trace.
    pub fn advance(&mut self) -> Result<(), FaultRuntimeError> {
        self.cursor = self
            .cursor
            .checked_add(1)
            .filter(|cursor| *cursor <= self.work_items.len())
            .ok_or(FaultRuntimeError::ReplayExhausted)?;
        Ok(())
    }

    /// Requires every replay work item to have been consumed.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError::ReplayMismatch`] when work items remain.
    pub fn require_exhausted(&self) -> Result<(), FaultRuntimeError> {
        if self.cursor == self.work_items.len() {
            Ok(())
        } else {
            Err(FaultRuntimeError::ReplayMismatch {
                index: self.cursor,
                expected: self.work_items[self.cursor].opportunity,
                observed: ContentHash::default(),
            })
        }
    }
}

/// Canonical adapter-owned checkpoint payload.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct AdapterCheckpointState {
    /// Exact adapter state semantic version.
    pub semantic_version: u16,
    /// Canonical state bytes.
    pub bytes: Vec<u8>,
    /// Digest of `bytes` for fingerprints and diagnostics.
    pub digest: ContentHash,
}

impl AdapterCheckpointState {
    /// Creates a bounded adapter state payload and computes its digest.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when bytes exceed the hard payload limit.
    pub fn new(
        semantic_version: u16,
        bytes: Vec<u8>,
        resource_limits: FaultResourceLimits,
    ) -> Result<Self, FaultRuntimeError> {
        let bytes_len = u64::try_from(bytes.len())
            .map_err(|_| FaultRuntimeError::CountOverflow("fat_checkpoint_bytes"))?;
        resource_limits
            .reserve("fat_checkpoint_bytes", 0, bytes_len)
            .map_err(FaultRuntimeError::ResourceLimit)?;
        let digest = ContentHash::from_bytes(&bytes);
        Ok(Self {
            semantic_version,
            bytes,
            digest,
        })
    }

    /// Verifies the payload bound and its content digest.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when bytes exceed the hard limit or the
    /// stored digest does not authenticate the bytes.
    pub fn validate(&self, resource_limits: FaultResourceLimits) -> Result<(), FaultRuntimeError> {
        let bytes_len = u64::try_from(self.bytes.len())
            .map_err(|_| FaultRuntimeError::CountOverflow("fat_checkpoint_bytes"))?;
        resource_limits
            .reserve("fat_checkpoint_bytes", 0, bytes_len)
            .map_err(FaultRuntimeError::ResourceLimit)?;
        if self.digest != ContentHash::from_bytes(&self.bytes) {
            return Err(FaultRuntimeError::AdapterCheckpointDigest);
        }
        Ok(())
    }
}

/// Complete mutable state required by a fat fault-runtime checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct FaultRuntimeCheckpoint {
    /// Exact runtime codec semantic version.
    pub semantic_version: u16,
    /// Exact admitted signal-plan identity.
    pub signal_plan: ContentHash,
    /// Exact scenario-owned resource contract.
    pub resource_limits: FaultResourceLimits,
    /// Sole complete signal/binding runtime continuation.
    pub binding_runtime: BindingRuntimeCheckpoint,
    /// Production-adapter mutable state.
    pub adapters: BTreeMap<FaultAdapter, AdapterCheckpointState>,
    /// Replay trace and cursor, when replaying.
    pub replay: Option<ResolvedEffectTrace>,
    /// Complete evaluated work items and their resolved effects.
    pub recorded_work_items: Vec<ResolvedReplayWorkItem>,
    /// Resolved-effect objects retained as checkpoint dependencies.
    pub retained_effects: BTreeSet<ContentHash>,
    /// Parent branch provenance for debugger edits.
    pub branch_parent: Option<ContentHash>,
    /// Whether backend visibility became ambiguous and execution is terminal.
    pub poisoned: bool,
}

impl FaultRuntimeCheckpoint {
    /// Encodes the complete continuation as deterministic CBOR.
    ///
    /// This is the authoritative aggregate representation for the checkpoint
    /// byte limit and content identity. Every nested mutable field participates.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when serialization fails, the byte count
    /// is not representable, or the complete checkpoint exceeds the plan's
    /// `fat_checkpoint_bytes` limit.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FaultRuntimeError> {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(self, &mut bytes)
            .map_err(|_| FaultRuntimeError::CheckpointEncoding)?;
        let byte_count = u64::try_from(bytes.len())
            .map_err(|_| FaultRuntimeError::CountOverflow("fat_checkpoint_bytes"))?;
        self.resource_limits
            .reserve("fat_checkpoint_bytes", 0, byte_count)
            .map_err(FaultRuntimeError::ResourceLimit)?;
        Ok(bytes)
    }

    /// Returns the content identity of the complete mutable continuation.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] under the same conditions as
    /// [`Self::canonical_bytes`].
    pub fn content_id(&self) -> Result<ContentHash, FaultRuntimeError> {
        Ok(ContentHash::from_bytes(&self.canonical_bytes()?))
    }

    /// Validates versions, all nested state, and hard collection limits.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when any state is malformed, unsupported,
    /// or exceeds a compiled bound.
    pub fn validate(
        &self,
        plan: &FaultSignalPlan,
        scenario_seed: ContentHash,
    ) -> Result<(), FaultRuntimeError> {
        let _ = self.canonical_bytes()?;
        let [program] = plan.programs() else {
            return Err(FaultRuntimeError::VersionOrIdentityMismatch);
        };
        let bindings = plan.bindings();
        if self.semantic_version != FAULT_RUNTIME_STATE_VERSION
            || self.signal_plan != plan.id()
            || self.resource_limits != plan.resource_limits()
            || self.binding_runtime.semantic_version != FAULT_RUNTIME_STATE_VERSION
            || self.binding_runtime.signal_program != program.id()
            || self.binding_runtime.resource_limits != self.resource_limits
            || self.binding_runtime.binding_contracts != bindings
        {
            return Err(FaultRuntimeError::VersionOrIdentityMismatch);
        }
        match self
            .binding_runtime
            .validate(program, bindings, scenario_seed, self.resource_limits)
        {
            Ok(()) => {}
            Err(BindingRuntimeError::ResourceLimit(error)) => {
                return Err(FaultRuntimeError::ResourceLimit(error));
            }
            Err(_) => return Err(FaultRuntimeError::VersionOrIdentityMismatch),
        }
        let search_overrides = u64::try_from(self.binding_runtime.search_overrides.len())
            .map_err(|_| FaultRuntimeError::CountOverflow("search_choices_per_state"))?;
        self.resource_limits
            .reserve("search_choices_per_state", 0, search_overrides)
            .map_err(FaultRuntimeError::ResourceLimit)?;
        self.binding_runtime
            .evaluator
            .validate_for_program(program, self.resource_limits)
            .map_err(|_| FaultRuntimeError::InvalidEvaluatorCheckpoint)?;
        let required_bindings = bindings
            .iter()
            .map(FaultBinding::id)
            .collect::<BTreeSet<_>>();
        if required_bindings.len() != bindings.len()
            || self
                .binding_runtime
                .bindings
                .keys()
                .collect::<BTreeSet<_>>()
                != required_bindings
        {
            return Err(FaultRuntimeError::IncompleteBindingState);
        }
        let required_adapters = BTreeSet::from([
            FaultAdapter::Network,
            FaultAdapter::Storage,
            FaultAdapter::Node,
        ]);
        if self.adapters.keys().copied().collect::<BTreeSet<_>>() != required_adapters {
            return Err(FaultRuntimeError::IncompleteAdapterState);
        }
        for state in self.adapters.values() {
            state.validate(self.resource_limits)?;
        }
        for (key, contribution) in self.binding_runtime.active.entries() {
            validate_contribution_key(key, contribution.request.kind())?;
            if !self
                .binding_runtime
                .bindings
                .get(&key.binding)
                .is_some_and(|state| state.active)
            {
                return Err(FaultRuntimeError::OrphanActiveContribution);
            }
        }
        if let Some(replay) = &self.replay {
            replay.validate(self.resource_limits)?;
        }
        let recorded_work_items = u64::try_from(self.recorded_work_items.len())
            .map_err(|_| FaultRuntimeError::CountOverflow("thin_replay_events"))?;
        self.resource_limits
            .reserve("thin_replay_events", 0, recorded_work_items)
            .map_err(FaultRuntimeError::ResourceLimit)?;
        let mut recorded_effects = 0_u64;
        for item in &self.recorded_work_items {
            item.validate()?;
            let additional = u64::try_from(item.records.len())
                .map_err(|_| FaultRuntimeError::CountOverflow("resolved_effect_records"))?;
            recorded_effects = recorded_effects
                .checked_add(additional)
                .ok_or(FaultRuntimeError::CountOverflow("resolved_effect_records"))?;
            self.resource_limits
                .reserve("resolved_effect_records", 0, recorded_effects)
                .map_err(FaultRuntimeError::ResourceLimit)?;
        }
        Ok(())
    }
}

/// Stable event classes emitted by signal-driven fault execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FaultObservationKind {
    /// A signal changed value.
    SignalTransition,
    /// A retained signal sample was evaluated.
    SignalSample,
    /// A stateful signal node changed state.
    SignalStateTransition,
    /// A binding installed a persistent contribution.
    BindingActivation,
    /// A binding removed its contribution.
    BindingDeactivation,
    /// An adapter exposed an opportunity.
    FaultOpportunity,
    /// A keyed hazard or search choice was resolved.
    EffectChoice,
    /// Simultaneous contributions were combined.
    EffectCombined,
    /// A production adapter applied an effect.
    EffectApplied,
    /// Application failed closed.
    EffectRejected,
    /// A directional network profile changed.
    NetworkProfile,
    /// A route, attachment, beam, or contact changed.
    AssociationTransition,
    /// A recorded outcome aligned with an opportunity.
    TraceAlignment,
}

impl FaultObservationKind {
    /// Returns the stable unified-event-log kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SignalTransition => "signal_transition",
            Self::SignalSample => "signal_sample",
            Self::SignalStateTransition => "signal_state_transition",
            Self::BindingActivation => "binding_activation",
            Self::BindingDeactivation => "binding_deactivation",
            Self::FaultOpportunity => "fault_opportunity",
            Self::EffectChoice => "effect_choice",
            Self::EffectCombined => "effect_combined",
            Self::EffectApplied => "effect_applied",
            Self::EffectRejected => "effect_rejected",
            Self::NetworkProfile => "network_profile",
            Self::AssociationTransition => "association_transition",
            Self::TraceAlignment => "trace_alignment",
        }
    }
}

/// One stable typed fault-observation record.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FaultObservation {
    /// Event schema semantic version.
    pub semantic_version: u16,
    /// Event class.
    pub kind: FaultObservationKind,
    /// Scheduler coordinate.
    pub coordinate: FaultCoordinate,
    /// Optional binding identity.
    pub binding: Option<FaultObjectId>,
    /// Optional concrete target.
    pub target: Option<ResolvedFaultTarget>,
    /// Optional opportunity identity.
    pub opportunity: Option<ContentHash>,
    /// Content-addressed typed evidence payload.
    pub evidence: ContentHash,
}

impl FaultObservation {
    /// Returns the stable material authenticated by event-log entries.
    #[must_use]
    pub fn canonical_material(&self) -> String {
        [
            format!("semantic_version={}", self.semantic_version),
            format!("kind={}", self.kind.as_str()),
            format!("coordinate.virtual_nanos={}", self.coordinate.virtual_nanos),
            format!(
                "coordinate.retired_instructions={}",
                self.coordinate
                    .retired_instructions
                    .map_or_else(|| String::from("none"), |value| value.to_string())
            ),
            format!(
                "binding={}",
                self.binding
                    .as_ref()
                    .map_or("none", |binding| binding.as_str())
            ),
            format!(
                "target={}",
                self.target.as_ref().map_or_else(
                    || String::from("none"),
                    ResolvedFaultTarget::canonical_material,
                )
            ),
            format!(
                "opportunity={}",
                self.opportunity
                    .map_or_else(|| String::from("none"), |value| value.to_hex())
            ),
            format!("evidence={}", self.evidence.to_hex()),
        ]
        .join("\n")
    }
}

/// Runtime, replay, capability, or checkpoint failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FaultRuntimeError {
    /// A capability manifest names a different adapter family.
    AdapterManifestMismatch,
    /// An action crossed adapter, target, phase, or lifetime contracts.
    AdapterActionMismatch,
    /// The adapter already owns one uncommitted transaction.
    AdapterTransactionPending,
    /// A commit or abort named no prepared transaction.
    UnknownAdapterTransaction,
    /// One atomic batch repeated an exact action identity.
    DuplicateAdapterAction,
    /// Rolling back a partially prepared cross-adapter batch failed.
    AdapterTransactionRollback,
    /// A collection count could not fit the canonical counter.
    CountOverflow(&'static str),
    /// A scenario-owned resource reservation failed.
    ResourceLimit(FaultResourceLimitError),
    /// Canonical evaluator checkpoint failed version, identity, or content validation.
    InvalidEvaluatorCheckpoint,
    /// Checkpoint omitted, duplicated, or added binding state.
    IncompleteBindingState,
    /// Checkpoint omitted or added production-adapter state.
    IncompleteAdapterState,
    /// Adapter payload digest does not authenticate its bytes.
    AdapterCheckpointDigest,
    /// Adapter checkpoint bytes are not the exact supported canonical schema.
    AdapterCheckpointCodec,
    /// The complete runtime checkpoint could not be encoded canonically.
    CheckpointEncoding,
    /// A monotone runtime sequence overflowed.
    SequenceOverflow(&'static str),
    /// A non-persistent effect entered the active table.
    NonPersistentActivation,
    /// Active key contradicts the effect registry.
    InvalidContributionKey,
    /// Active contribution has no active owning binding state.
    OrphanActiveContribution,
    /// A nested target or record contract failed.
    Contract(FaultContractError),
    /// Live backend omitted a required capability.
    MissingCapability(FaultCapabilityId),
    /// Replay trace or cursor is malformed.
    InvalidReplayTrace,
    /// Replay consumed every expected effect.
    ReplayExhausted,
    /// Encountered opportunity differs from the locked record.
    ReplayMismatch {
        /// Record index.
        index: usize,
        /// Expected opportunity identity.
        expected: Option<ContentHash>,
        /// Observed opportunity identity.
        observed: ContentHash,
    },
    /// Locked replay encountered a different live before-state digest.
    ReplayPreconditionMismatch {
        /// Exact resolved action identity.
        action: ContentHash,
        /// Digest retained by the replay record.
        expected: ContentHash,
        /// Digest observed by the live backend before mutation.
        observed: ContentHash,
    },
    /// Runtime semantic version or program identity differs.
    VersionOrIdentityMismatch,
}

impl fmt::Display for FaultRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid fault runtime state: {self:?}")
    }
}

impl Error for FaultRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ResourceLimit(error) => Some(error),
            Self::Contract(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object_id(value: &str) -> FaultObjectId {
        match FaultObjectId::parse(value) {
            Ok(id) => id,
            Err(error) => panic!("test object ID must be valid: {error}"),
        }
    }

    #[test]
    fn healing_removes_only_one_contributor() {
        let target = ResolvedFaultTarget::NetworkSegment {
            segment: object_id("segment-a"),
            direction: FaultDirection::AToB,
        };
        let request = match EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Persistent,
            EffectSpecification::Network(NetworkEffectSpecification::Availability {
                state: NetworkAvailabilityState::Down,
                queued_policy: NetworkInFlightPolicy::Drop,
                in_flight_policy: NetworkInFlightPolicy::Drop,
            }),
        ) {
            Ok(value) => value,
            Err(error) => panic!("test request must be valid: {error}"),
        };
        let mut table = ActiveContributionTable::default();
        for name in ["binding-a", "binding-b"] {
            let result = table.activate(
                ActiveContributionKey {
                    target: target.clone(),
                    phase: FaultPhase::Admit,
                    effect: EffectKind::NetworkAvailability,
                    binding: object_id(name),
                },
                ActiveEffectContribution {
                    request: Arc::new(request.clone()),
                    mapped_parameters: ContentHash::from_bytes(name.as_bytes()),
                    mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
                    transition_sequence: 1,
                },
                FaultResourceLimits::default(),
            );
            assert!(result.is_ok());
        }
        let removed = table.deactivate(&ActiveContributionKey {
            target,
            phase: FaultPhase::Admit,
            effect: EffectKind::NetworkAvailability,
            binding: object_id("binding-a"),
        });
        assert!(removed.is_some());
        assert_eq!(table.entries().len(), 1);
        assert_eq!(table.composition_groups()[0].contributors.len(), 1);
    }

    #[test]
    fn active_contributions_obey_the_plan_owned_per_target_limit() {
        let target = ResolvedFaultTarget::NetworkSegment {
            segment: object_id("segment-limited"),
            direction: FaultDirection::AToB,
        };
        let request = EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Persistent,
            EffectSpecification::Network(NetworkEffectSpecification::Availability {
                state: NetworkAvailabilityState::Down,
                queued_policy: NetworkInFlightPolicy::Drop,
                in_flight_policy: NetworkInFlightPolicy::Drop,
            }),
        )
        .unwrap_or_else(|error| panic!("test request must be valid: {error}"));
        let mut limits = FaultResourceLimits::default();
        limits.active_contributions_per_target = 1;
        let mut table = ActiveContributionTable::default();
        for name in ["binding-first", "binding-rejected"] {
            let result = table.activate(
                ActiveContributionKey {
                    target: target.clone(),
                    phase: FaultPhase::Admit,
                    effect: EffectKind::NetworkAvailability,
                    binding: object_id(name),
                },
                ActiveEffectContribution {
                    request: Arc::new(request.clone()),
                    mapped_parameters: ContentHash::from_bytes(name.as_bytes()),
                    mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
                    transition_sequence: 1,
                },
                limits,
            );
            if name == "binding-first" {
                assert!(result.is_ok());
            } else {
                assert!(matches!(
                    result,
                    Err(FaultRuntimeError::ResourceLimit(
                        FaultResourceLimitError::Exceeded {
                            field: "active_contributions_per_target",
                            current: 1,
                            requested: 1,
                            configured: 1,
                            ..
                        }
                    ))
                ));
            }
        }
        assert_eq!(table.entries().len(), 1);
    }

    #[test]
    fn adapter_checkpoint_digest_is_revalidated() {
        let mut state =
            match AdapterCheckpointState::new(1, vec![1, 2, 3], FaultResourceLimits::default()) {
                Ok(value) => value,
                Err(error) => panic!("test adapter state must be valid: {error}"),
            };
        state.bytes.push(4);
        assert_eq!(
            state.validate(FaultResourceLimits::default()),
            Err(FaultRuntimeError::AdapterCheckpointDigest)
        );
    }

    #[test]
    fn composition_identity_includes_the_concrete_target() {
        let contributor = CompositionContributor {
            binding: object_id("binding-a"),
            parameters: ContentHash::from_bytes(b"same"),
            mapping_output: ResolvedMappingOutput::Activation { active: true },
        };
        let first = EffectComposition::new(
            ResolvedFaultTarget::NetworkSegment {
                segment: object_id("segment-a"),
                direction: FaultDirection::AToB,
            },
            FaultPhase::Admit,
            EffectKind::NetworkAvailability,
            contributor.clone(),
        );
        let second = EffectComposition::new(
            ResolvedFaultTarget::NetworkSegment {
                segment: object_id("segment-b"),
                direction: FaultDirection::AToB,
            },
            FaultPhase::Admit,
            EffectKind::NetworkAvailability,
            contributor,
        );
        assert_ne!(first.digest, second.digest);
    }
}
