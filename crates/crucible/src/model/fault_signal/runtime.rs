//! Deterministic binding, composition, checkpoint, search, and replay state.
//!
//! The types in this module are the mutable spine shared by production
//! adapters. Every state item that can affect a later opportunity is bounded,
//! ordered, content-addressed, and represented in [`FaultRuntimeCheckpoint`].

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use super::*;

/// Semantic version of runtime/checkpoint state.
pub const FAULT_RUNTIME_STATE_VERSION: u16 = 1;
/// Maximum serialized bytes retained for one signal node.
pub const HARD_SIGNAL_NODE_RUNTIME_BYTES: usize = 16_777_216;
/// Maximum active contributions in one run.
pub const HARD_ACTIVE_CONTRIBUTIONS: usize = 262_144;
/// Maximum keyed search overrides in one run.
pub const HARD_SEARCH_OVERRIDES: usize = 262_144;
/// Maximum resolved records retained directly by one replay trace.
pub const HARD_RESOLVED_EFFECT_RECORDS: usize = 4_194_304;
/// Maximum bytes in one adapter checkpoint payload.
pub const HARD_ADAPTER_CHECKPOINT_BYTES: usize = 268_435_456;

/// Runtime state for one signal node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalNodeRuntimeState {
    /// Last coordinate at which the node was evaluated.
    pub last_coordinate: FaultCoordinate,
    /// Canonical state-machine or operator bytes.
    pub state_bytes: Vec<u8>,
    /// Optional normalized-trace chunk identity.
    pub trace_chunk: Option<ContentHash>,
    /// Next sample or event index in that chunk.
    pub trace_entry: Option<u32>,
    /// Digest of the last produced value.
    pub last_value: Option<ContentHash>,
}

impl SignalNodeRuntimeState {
    /// Validates bounded bytes and trace-cursor completeness.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when state exceeds its declared or hard
    /// bound, or exactly one half of a trace cursor is present.
    pub fn validate(&self, declared_state_bytes: u64) -> Result<(), FaultRuntimeError> {
        let length = u64::try_from(self.state_bytes.len())
            .map_err(|_| FaultRuntimeError::CountOverflow("signal_state_bytes"))?;
        let hard = u64::try_from(HARD_SIGNAL_NODE_RUNTIME_BYTES)
            .map_err(|_| FaultRuntimeError::CountOverflow("signal_state_hard_limit"))?;
        if length > declared_state_bytes || length > hard {
            return Err(FaultRuntimeError::StateLimit {
                field: "signal_state_bytes",
                actual: length,
                configured: declared_state_bytes.min(hard),
            });
        }
        if self.trace_chunk.is_some() != self.trace_entry.is_some() {
            return Err(FaultRuntimeError::IncompleteTraceCursor);
        }
        Ok(())
    }
}

/// Mutable activation state for one binding.
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveEffectContribution {
    /// Typed validated request.
    pub request: EffectRequest,
    /// Digest of canonical parameters after mapping.
    pub mapped_parameters: ContentHash,
    /// Binding transition sequence which installed this contribution.
    pub transition_sequence: u64,
}

/// Canonical active-contribution table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
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
    ) -> Result<Option<ActiveEffectContribution>, FaultRuntimeError> {
        if contribution.request.lifetime() != EffectLifetime::Persistent {
            return Err(FaultRuntimeError::NonPersistentActivation);
        }
        validate_contribution_key(&key, contribution.request.kind())?;
        if !self.entries.contains_key(&key) && self.entries.len() == HARD_ACTIVE_CONTRIBUTIONS {
            return Err(FaultRuntimeError::StateLimit {
                field: "active_contributions",
                actual: u64::try_from(self.entries.len() + 1)
                    .map_err(|_| FaultRuntimeError::CountOverflow("active_contributions"))?,
                configured: u64::try_from(HARD_ACTIVE_CONTRIBUTIONS)
                    .map_err(|_| FaultRuntimeError::CountOverflow("active_contributions"))?,
            });
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SearchChoiceId(ContentHash);

impl SearchChoiceId {
    /// Builds the decision-domain-separated identity required for replay.
    #[must_use]
    pub fn new(
        program: ContentHash,
        binding: &FaultObjectId,
        opportunity: Option<ContentHash>,
        candidates: ContentHash,
    ) -> Self {
        let material = format!(
            "program={};binding={};opportunity={};candidates={};",
            program.to_hex(),
            binding.as_str(),
            opportunity.map_or_else(|| String::from("none"), |value| value.to_hex()),
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchOverride {
    /// Chosen zero-based candidate index.
    pub candidate_index: u32,
    /// Digest of the exact finite candidate set.
    pub candidates_digest: ContentHash,
    /// Parent branch, if this choice forked an earlier search branch.
    pub parent_branch: Option<ContentHash>,
}

/// Authoritative replay behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FaultReplayMode {
    /// Reevaluates causes and verifies every resolved record.
    RecomputedCause,
    /// Uses exact resolved effects after strict context verification.
    LockedEffect,
    /// Uses an exact or explicitly bucketed network outcome stream.
    OutcomeOnlyNetwork,
}

/// Ordered resolved-effect trace and its replay cursor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedEffectTrace {
    /// Replay mode encoded in the reproduction artifact.
    pub mode: FaultReplayMode,
    /// Exact ordered effect records.
    pub records: Vec<ResolvedEffectRecord>,
    /// Next record to consume.
    pub cursor: usize,
}

impl ResolvedEffectTrace {
    /// Validates trace bounds and every replay record.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] for an oversized trace, invalid cursor,
    /// invalid record, or non-network record in outcome-only network mode.
    pub fn validate(&self) -> Result<(), FaultRuntimeError> {
        if self.records.len() > HARD_RESOLVED_EFFECT_RECORDS || self.cursor > self.records.len() {
            return Err(FaultRuntimeError::InvalidReplayTrace);
        }
        for record in &self.records {
            record.validate().map_err(FaultRuntimeError::Contract)?;
            if self.mode == FaultReplayMode::OutcomeOnlyNetwork
                && record.effect.descriptor().adapter != FaultAdapter::Network
            {
                return Err(FaultRuntimeError::InvalidReplayTrace);
            }
        }
        Ok(())
    }

    /// Consumes the next record only if exact opportunity context matches.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError::ReplayExhausted`] at end of trace or
    /// [`FaultRuntimeError::ReplayMismatch`] without advancing on mismatch.
    pub fn consume(
        &mut self,
        opportunity: &FaultOpportunity,
        effect: EffectKind,
        capability: &FaultCapabilityId,
        precondition: Option<ContentHash>,
    ) -> Result<&ResolvedEffectRecord, FaultRuntimeError> {
        let record = self
            .records
            .get(self.cursor)
            .ok_or(FaultRuntimeError::ReplayExhausted)?;
        let matches = record.effect == effect
            && record.target == *opportunity.target()
            && record.opportunity == Some(opportunity.id())
            && record.coordinate == opportunity.coordinate()
            && record.phase == opportunity.phase()
            && record.capability == *capability
            && record.precondition_digest == precondition;
        if !matches {
            return Err(FaultRuntimeError::ReplayMismatch {
                index: self.cursor,
                expected: record.opportunity,
                observed: opportunity.id(),
            });
        }
        self.cursor += 1;
        Ok(record)
    }
}

/// Canonical adapter-owned checkpoint payload.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    pub fn new(semantic_version: u16, bytes: Vec<u8>) -> Result<Self, FaultRuntimeError> {
        if bytes.len() > HARD_ADAPTER_CHECKPOINT_BYTES {
            return Err(FaultRuntimeError::StateLimit {
                field: "adapter_checkpoint_bytes",
                actual: u64::try_from(bytes.len())
                    .map_err(|_| FaultRuntimeError::CountOverflow("adapter_checkpoint_bytes"))?,
                configured: u64::try_from(HARD_ADAPTER_CHECKPOINT_BYTES)
                    .map_err(|_| FaultRuntimeError::CountOverflow("adapter_checkpoint_bytes"))?,
            });
        }
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
    pub fn validate(&self) -> Result<(), FaultRuntimeError> {
        if self.bytes.len() > HARD_ADAPTER_CHECKPOINT_BYTES {
            return Err(FaultRuntimeError::StateLimit {
                field: "adapter_checkpoint_bytes",
                actual: u64::try_from(self.bytes.len())
                    .map_err(|_| FaultRuntimeError::CountOverflow("adapter_checkpoint_bytes"))?,
                configured: u64::try_from(HARD_ADAPTER_CHECKPOINT_BYTES)
                    .map_err(|_| FaultRuntimeError::CountOverflow("adapter_checkpoint_bytes"))?,
            });
        }
        if self.digest != ContentHash::from_bytes(&self.bytes) {
            return Err(FaultRuntimeError::AdapterCheckpointDigest);
        }
        Ok(())
    }
}

/// Complete mutable state required by a fat fault-runtime checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultRuntimeCheckpoint {
    /// Exact runtime codec semantic version.
    pub semantic_version: u16,
    /// Signal-program content identity.
    pub signal_program: ContentHash,
    /// Exact evaluator semantic version.
    pub evaluator_version: u16,
    /// Per-node mutable evaluator state.
    pub signals: BTreeMap<SignalId, SignalNodeRuntimeState>,
    /// Per-binding transition and mapping state.
    pub bindings: BTreeMap<FaultObjectId, BindingRuntimeState>,
    /// Active persistent contributions.
    pub active: ActiveContributionTable,
    /// Production-adapter mutable state.
    pub adapters: BTreeMap<FaultAdapter, AdapterCheckpointState>,
    /// Replay trace and cursor, when replaying.
    pub replay: Option<ResolvedEffectTrace>,
    /// Concrete keyed explorer overrides.
    pub search_overrides: BTreeMap<SearchChoiceId, SearchOverride>,
    /// Resolved-effect objects retained as checkpoint dependencies.
    pub retained_effects: BTreeSet<ContentHash>,
    /// Parent branch provenance for debugger edits.
    pub branch_parent: Option<ContentHash>,
}

impl FaultRuntimeCheckpoint {
    /// Validates versions, all nested state, and hard collection limits.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when any state is malformed, unsupported,
    /// or exceeds a compiled bound.
    pub fn validate(
        &self,
        program: &SignalProgram,
        bindings: &[FaultBinding],
    ) -> Result<(), FaultRuntimeError> {
        if self.semantic_version != FAULT_RUNTIME_STATE_VERSION
            || self.evaluator_version != SIGNAL_EVALUATOR_VERSION
            || self.signal_program != program.id()
        {
            return Err(FaultRuntimeError::VersionOrIdentityMismatch);
        }
        if self.active.entries().len() > HARD_ACTIVE_CONTRIBUTIONS
            || self.search_overrides.len() > HARD_SEARCH_OVERRIDES
        {
            return Err(FaultRuntimeError::StateLimit {
                field: "runtime_collections",
                actual: u64::try_from(self.active.entries().len().max(self.search_overrides.len()))
                    .map_err(|_| FaultRuntimeError::CountOverflow("runtime_collections"))?,
                configured: u64::try_from(HARD_ACTIVE_CONTRIBUTIONS.max(HARD_SEARCH_OVERRIDES))
                    .map_err(|_| FaultRuntimeError::CountOverflow("runtime_collections"))?,
            });
        }
        let nodes = program
            .nodes()
            .iter()
            .map(|node| (&node.id, node))
            .collect::<BTreeMap<_, _>>();
        let required_signal_state = program
            .nodes()
            .iter()
            .filter(|node| {
                matches!(node.kind, SignalNodeKind::Stateful { .. })
                    || matches!(
                        node.kind,
                        SignalNodeKind::Source(SignalSourceSpecification::Trace { .. })
                    )
            })
            .map(|node| &node.id)
            .collect::<BTreeSet<_>>();
        if self.signals.keys().collect::<BTreeSet<_>>() != required_signal_state {
            return Err(FaultRuntimeError::IncompleteSignalState);
        }
        for (id, state) in &self.signals {
            let node = nodes
                .get(id)
                .ok_or_else(|| FaultRuntimeError::UnknownSignal(id.clone()))?;
            let declared = match node.kind {
                SignalNodeKind::Stateful { state_bytes, .. } => state_bytes,
                _ => 0,
            };
            state.validate(declared)?;
        }
        let required_bindings = bindings
            .iter()
            .map(FaultBinding::id)
            .collect::<BTreeSet<_>>();
        if required_bindings.len() != bindings.len()
            || self.bindings.keys().collect::<BTreeSet<_>>() != required_bindings
        {
            return Err(FaultRuntimeError::IncompleteBindingState);
        }
        let required_adapters = bindings
            .iter()
            .map(|binding| binding.effect().kind().descriptor().adapter)
            .collect::<BTreeSet<_>>();
        if self.adapters.keys().copied().collect::<BTreeSet<_>>() != required_adapters {
            return Err(FaultRuntimeError::IncompleteAdapterState);
        }
        for state in self.adapters.values() {
            state.validate()?;
        }
        for (key, contribution) in self.active.entries() {
            validate_contribution_key(key, contribution.request.kind())?;
            if !self
                .bindings
                .get(&key.binding)
                .is_some_and(|state| state.active)
            {
                return Err(FaultRuntimeError::OrphanActiveContribution);
            }
        }
        if let Some(replay) = &self.replay {
            replay.validate()?;
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
    FaultChoice,
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

/// One stable typed fault-observation record.
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// Runtime, replay, capability, or checkpoint failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FaultRuntimeError {
    /// A collection count could not fit the canonical counter.
    CountOverflow(&'static str),
    /// Bounded mutable state exceeded its limit.
    StateLimit {
        /// Limit field.
        field: &'static str,
        /// Observed usage.
        actual: u64,
        /// Effective maximum.
        configured: u64,
    },
    /// Trace cursor omitted its chunk or entry half.
    IncompleteTraceCursor,
    /// Checkpoint omitted or added signal-node state.
    IncompleteSignalState,
    /// Checkpoint omitted, duplicated, or added binding state.
    IncompleteBindingState,
    /// Checkpoint omitted or added production-adapter state.
    IncompleteAdapterState,
    /// Adapter payload digest does not authenticate its bytes.
    AdapterCheckpointDigest,
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
    /// Runtime semantic version or program identity differs.
    VersionOrIdentityMismatch,
    /// Checkpoint contains state for an unknown signal.
    UnknownSignal(SignalId),
}

impl fmt::Display for FaultRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid fault runtime state: {self:?}")
    }
}

impl Error for FaultRuntimeError {}

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
                    request: request.clone(),
                    mapped_parameters: ContentHash::from_bytes(name.as_bytes()),
                    transition_sequence: 1,
                },
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
    fn trace_cursor_must_be_complete() {
        let state = SignalNodeRuntimeState {
            last_coordinate: FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            state_bytes: Vec::new(),
            trace_chunk: Some(ContentHash::from_bytes(b"chunk")),
            trace_entry: None,
            last_value: None,
        };
        assert_eq!(
            state.validate(0),
            Err(FaultRuntimeError::IncompleteTraceCursor)
        );
    }

    #[test]
    fn adapter_checkpoint_digest_is_revalidated() {
        let mut state = match AdapterCheckpointState::new(1, vec![1, 2, 3]) {
            Ok(value) => value,
            Err(error) => panic!("test adapter state must be valid: {error}"),
        };
        state.bytes.push(4);
        assert_eq!(
            state.validate(),
            Err(FaultRuntimeError::AdapterCheckpointDigest)
        );
    }

    #[test]
    fn composition_identity_includes_the_concrete_target() {
        let contributor = CompositionContributor {
            binding: object_id("binding-a"),
            parameters: ContentHash::from_bytes(b"same"),
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
