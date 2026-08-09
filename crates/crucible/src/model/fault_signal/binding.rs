//! Validated bindings from signal outputs to typed production effects.
//!
//! Bindings are the only bridge between cause signals and adapter mutations.
//! Selectors, sampling, mapping, search, and observability are closed enums so
//! scenario data cannot invoke arbitrary adapter behavior.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use super::*;

/// Maximum concrete targets produced by one selector.
pub const HARD_BINDING_TARGET_LIMIT: usize = 65_536;
/// Maximum admitted fault bindings in one scenario.
pub const HARD_FAULT_BINDING_LIMIT: usize = 131_072;
/// Maximum exported signal inputs consumed by one binding.
pub const HARD_BINDING_SIGNAL_INPUT_LIMIT: usize = 128;
/// Maximum finite candidates in one search policy or transfer function.
pub const HARD_SEARCH_CANDIDATE_LIMIT: usize = 4_096;
/// Maximum search decisions retained in one materialized runtime state.
pub const HARD_SEARCH_CHOICES_PER_STATE: u64 = 262_144;
/// Maximum named transition tables or service profiles in one registry.
pub const HARD_MAPPING_DECLARATIONS: usize = 4_096;

/// When a binding samples its signal inputs.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum BindingSampling {
    /// Samples at scheduler boundaries.
    AtBoundary,
    /// Samples for each matching adapter opportunity.
    AtOpportunity,
    /// Samples whenever an input changes.
    AtChange,
    /// Samples on an exact positive virtual-time cadence.
    CadenceNanos(PositiveU64),
    /// Samples a typed event with explicit parent-coordinate provenance.
    AtEvent(BindingEventParent),
}

/// Explicit parent coordinate for one event-domain binding sample.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum BindingEventParent {
    /// Event is scheduled directly on global virtual time.
    VirtualTime,
    /// Event is scheduled on one explicit node retired-instruction counter.
    NodeCounter {
        /// Stable node-counter identity.
        node: SignalId,
    },
    /// Event is emitted by the current adapter operation.
    OpportunityOperation,
    /// Event is emitted by the current adapter state boundary.
    OpportunityState,
}

impl BindingEventParent {
    const fn requires_opportunity(&self) -> bool {
        matches!(self, Self::OpportunityOperation | Self::OpportunityState)
    }
}

/// A finite, homogeneous, already-resolved selector result.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct ResolvedTargetSet {
    targets: Vec<ResolvedFaultTarget>,
    allow_empty: bool,
}

impl<'de> serde::Deserialize<'de> for ResolvedTargetSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            targets: Vec<ResolvedFaultTarget>,
            allow_empty: bool,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.targets, wire.allow_empty).map_err(serde::de::Error::custom)
    }
}

impl ResolvedTargetSet {
    /// Validates and canonicalizes concrete targets for one binding.
    ///
    /// # Errors
    ///
    /// Returns [`BindingError`] for an unpermitted empty set, an oversized set,
    /// a malformed or duplicate target, or targets from multiple adapters.
    pub fn new(
        mut targets: Vec<ResolvedFaultTarget>,
        allow_empty: bool,
    ) -> Result<Self, BindingError> {
        if targets.is_empty() && !allow_empty {
            return Err(BindingError::EmptySelector);
        }
        if targets.len() > HARD_BINDING_TARGET_LIMIT {
            return Err(BindingError::TooManyTargets {
                actual: targets.len(),
                hard: HARD_BINDING_TARGET_LIMIT,
            });
        }
        for target in &targets {
            target.validate().map_err(BindingError::Target)?;
        }
        targets.sort();
        if targets.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(BindingError::DuplicateTarget);
        }
        if let Some(first) = targets.first()
            && targets
                .iter()
                .any(|target| target.kind().adapter() != first.kind().adapter())
        {
            return Err(BindingError::MixedTargetAdapters);
        }
        Ok(Self {
            targets,
            allow_empty,
        })
    }

    /// Returns targets in canonical identity order.
    #[must_use]
    pub fn targets(&self) -> &[ResolvedFaultTarget] {
        &self.targets
    }

    /// Returns whether no matches were explicitly permitted.
    #[must_use]
    pub const fn allow_empty(&self) -> bool {
        self.allow_empty
    }

    /// Returns the adapter domain when the set is nonempty.
    #[must_use]
    pub fn adapter(&self) -> Option<FaultAdapter> {
        self.targets.first().map(|target| target.kind().adapter())
    }
}

/// Closed selector provenance retained after world resolution.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum TargetSelector {
    /// One explicitly named target.
    Exact(ResolvedTargetSet),
    /// A canonical explicit set from one adapter domain.
    TargetSet(ResolvedTargetSet),
    /// A static fault-domain query resolved during admission.
    FaultDomain {
        /// Fault-domain identity.
        domain: FaultObjectId,
        /// Canonical finite result.
        resolved: ResolvedTargetSet,
    },
    /// Versioned dynamic network-path membership.
    DynamicPath {
        /// Declared path identity.
        path: FaultObjectId,
        /// Initial canonical membership.
        initial: ResolvedTargetSet,
        /// Membership-state-machine semantic version.
        membership_semantic_version: u16,
    },
}

impl TargetSelector {
    /// Returns the admitted concrete membership.
    #[must_use]
    pub const fn resolved(&self) -> &ResolvedTargetSet {
        match self {
            Self::Exact(targets) | Self::TargetSet(targets) => targets,
            Self::FaultDomain { resolved, .. } => resolved,
            Self::DynamicPath { initial, .. } => initial,
        }
    }

    fn validate(&self) -> Result<(), BindingError> {
        if let Self::Exact(targets) = self
            && targets.targets().len() != 1
        {
            return Err(BindingError::ExactSelectorCardinality);
        }
        if let Self::DynamicPath {
            initial,
            membership_semantic_version,
            ..
        } = self
        {
            if *membership_semantic_version != 1 {
                return Err(BindingError::SelectorVersion {
                    actual: *membership_semantic_version,
                });
            }
            if initial
                .adapter()
                .is_some_and(|adapter| adapter != FaultAdapter::Network)
            {
                return Err(BindingError::DynamicSelectorAdapter);
            }
        }
        Ok(())
    }
}

/// Closed comparison vocabulary used by threshold activation.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdComparison {
    /// Activates below the threshold.
    LessThan,
    /// Activates at or below the threshold.
    LessThanOrEqual,
    /// Activates above the threshold.
    GreaterThan,
    /// Activates at or above the threshold.
    GreaterThanOrEqual,
}

/// Effect fields which a signal may drive dynamically.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum MappedEffectParameter {
    /// Probability in millionths.
    Probability,
    /// Delay, timeout, residence, or recovery duration.
    DurationNanos,
    /// Network bit rate.
    BitsPerSecond,
    /// Storage or memory byte rate.
    BytesPerSecond,
    /// I/O or service operation rate.
    OperationsPerSecond,
    /// Exact dimensionless capacity or rate multiplier.
    CapacityRatio,
    /// Signed clock or data offset in the binding's declared unit.
    SignedOffset,
    /// Positive queue, burst, retry, or mutation count.
    UnsignedCount,
}

impl MappedEffectParameter {
    fn accepts(self, shape: &SignalShape) -> bool {
        match self {
            Self::Probability => {
                shape.value_type == SignalValueType::ProbabilityMillionths
                    && shape.unit == SignalUnit::ProbabilityMillionths
                    && shape.scale_decimal_exponent == 0
            }
            Self::DurationNanos => {
                shape.value_type == SignalValueType::DurationNanos
                    && shape.unit == SignalUnit::VirtualNanoseconds
            }
            Self::BitsPerSecond => {
                matches!(
                    shape.value_type,
                    SignalValueType::U64 | SignalValueType::RatePerSecond
                ) && shape.unit == SignalUnit::BitsPerSecond
            }
            Self::BytesPerSecond => {
                matches!(
                    shape.value_type,
                    SignalValueType::U64 | SignalValueType::RatePerSecond
                ) && shape.unit == SignalUnit::BytesPerSecond
            }
            Self::OperationsPerSecond => {
                matches!(
                    shape.value_type,
                    SignalValueType::U64 | SignalValueType::RatePerSecond
                ) && shape.unit == SignalUnit::OperationsPerSecond
            }
            Self::CapacityRatio => {
                shape.value_type == SignalValueType::Ratio
                    && shape.unit == SignalUnit::Dimensionless
            }
            Self::SignedOffset => shape.value_type == SignalValueType::I64,
            Self::UnsignedCount => {
                shape.value_type == SignalValueType::U64 && shape.unit == SignalUnit::Dimensionless
            }
        }
    }

    fn belongs_to(self, effect: EffectKind) -> bool {
        match self {
            Self::Probability => matches!(
                effect,
                EffectKind::NetworkFrameLoss
                    | EffectKind::NetworkJitter
                    | EffectKind::NetworkDuplicate
                    | EffectKind::NetworkReorder
                    | EffectKind::NetworkDetectedFrameError
                    | EffectKind::StorageOperationFailure
                    | EffectKind::StorageLatency
                    | EffectKind::StorageCompletionReorder
                    | EffectKind::StorageDuplicateCompletion
                    | EffectKind::MemoryEccEvent
                    | EffectKind::InterruptDisposition
            ),
            Self::DurationNanos => matches!(
                effect,
                EffectKind::NetworkFlap
                    | EffectKind::NetworkPropagationDelay
                    | EffectKind::NetworkAccessDelay
                    | EffectKind::NetworkJitter
                    | EffectKind::NetworkRouteTransition
                    | EffectKind::NetworkAssociation
                    | EffectKind::NetworkContact
                    | EffectKind::StorageLatency
                    | EffectKind::StorageStallTimeout
                    | EffectKind::InterruptDisposition
                    | EffectKind::MemoryService
                    | EffectKind::ClockTransform
            ),
            Self::BitsPerSecond => matches!(
                effect,
                EffectKind::NetworkNegotiatedMode
                    | EffectKind::NetworkServiceCurve
                    | EffectKind::NetworkTokenBucket
                    | EffectKind::NetworkControlPlaneService
                    | EffectKind::NetworkSharedMedium
                    | EffectKind::NetworkRfChannel
                    | EffectKind::NetworkCustodyQueue
            ),
            Self::BytesPerSecond => matches!(
                effect,
                EffectKind::StorageService
                    | EffectKind::StorageArrayState
                    | EffectKind::MemoryService
                    | EffectKind::AcceleratorService
            ),
            Self::OperationsPerSecond => matches!(
                effect,
                EffectKind::StorageService
                    | EffectKind::StorageArrayState
                    | EffectKind::MemoryService
                    | EffectKind::InterruptStorm
                    | EffectKind::AcceleratorService
            ),
            Self::CapacityRatio => matches!(
                effect,
                EffectKind::NetworkProfileDelta
                    | EffectKind::NetworkServiceCurve
                    | EffectKind::NetworkSharedMedium
                    | EffectKind::NetworkRfChannel
                    | EffectKind::StorageService
                    | EffectKind::CpuService
                    | EffectKind::MemoryService
                    | EffectKind::ClockTransform
                    | EffectKind::AcceleratorService
            ),
            Self::SignedOffset => matches!(
                effect,
                EffectKind::NetworkProfileDelta
                    | EffectKind::NetworkRfChannel
                    | EffectKind::ClockTransform
            ),
            Self::UnsignedCount => matches!(
                effect,
                EffectKind::NetworkTokenBucket
                    | EffectKind::NetworkQueuePolicy
                    | EffectKind::NetworkDuplicate
                    | EffectKind::NetworkReorder
                    | EffectKind::NetworkMtu
                    | EffectKind::NetworkCustodyQueue
                    | EffectKind::StorageReportedCapacity
                    | EffectKind::StorageService
                    | EffectKind::StorageCompletionReorder
                    | EffectKind::StorageDuplicateCompletion
                    | EffectKind::StorageMediaRange
                    | EffectKind::StorageFlashState
                    | EffectKind::CpuService
                    | EffectKind::CpuInstructionTransform
                    | EffectKind::InterruptStorm
                    | EffectKind::MemoryRegionState
                    | EffectKind::MemoryService
            ),
        }
    }

    pub(super) fn accepts_value(self, value: &SignalValue) -> bool {
        match self {
            Self::Probability => {
                matches!(value, SignalValue::ProbabilityMillionths(value) if *value <= 1_000_000)
            }
            Self::DurationNanos => matches!(value, SignalValue::DurationNanos(_)),
            Self::BitsPerSecond | Self::BytesPerSecond | Self::OperationsPerSecond => {
                matches!(value, SignalValue::U64(_) | SignalValue::RatePerSecond(_))
            }
            Self::CapacityRatio => matches!(value, SignalValue::Ratio(_)),
            Self::SignedOffset => matches!(value, SignalValue::I64(_)),
            Self::UnsignedCount => matches!(value, SignalValue::U64(_)),
        }
    }
}

/// One exact piecewise mapping point.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct BindingMapPoint {
    /// Strictly increasing input value.
    pub input: SignalValue,
    /// Corresponding output value.
    pub output: SignalValue,
}

/// Closed signal-to-effect mapping vocabulary.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum BindingMapping {
    /// A Boolean signal controls persistent activation.
    ActiveWhenTrue {
        /// Inverts the signal before activation.
        invert: bool,
    },
    /// A closed enum signal activates for one variant.
    ActiveWhenEqual {
        /// Required enum variant.
        value: SignalId,
    },
    /// Numeric threshold activation with hysteresis and residence.
    Threshold {
        /// Activation comparison.
        comparison: ThresholdComparison,
        /// Activation threshold.
        threshold: SignalValue,
        /// Optional distinct clearing threshold.
        clear_threshold: Option<SignalValue>,
        /// Minimum residence at a candidate state.
        residence_nanos: u64,
    },
    /// Maps one signal into one registered effect field.
    MapParameter {
        /// Destination field contract.
        parameter: MappedEffectParameter,
    },
    /// Maps through an exact finite transfer function.
    PiecewiseParameter {
        /// Destination field contract.
        parameter: MappedEffectParameter,
        /// Strictly increasing input points.
        points: Vec<BindingMapPoint>,
        /// Exact rounding policy.
        rounding: SignalRounding,
        /// Exact overflow policy.
        overflow: SignalOverflow,
    },
    /// Evaluates one keyed probability at every matching opportunity.
    Hazard,
    /// Produces one impulse for each typed event identity.
    ImpulseOnEvent,
    /// Requests a registered exhaustive adapter transition.
    StateTransition {
        /// Closed transition-table identity.
        transition_table: FaultObjectId,
    },
    /// Controls a registered time-varying service model.
    ServiceProfile {
        /// Closed service-profile identity.
        service_profile: FaultObjectId,
    },
}

/// Closed, fully typed mapping result passed to production adapters.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum ResolvedMappingOutput {
    /// A Boolean, enum, or threshold mapping changed persistent activation.
    Activation {
        /// Resulting persistent activation state.
        active: bool,
    },
    /// One dynamic effect parameter was resolved to a canonical value.
    Parameter {
        /// Destination field contract.
        parameter: MappedEffectParameter,
        /// Canonical mapped value.
        value: SignalValue,
    },
    /// A keyed hazard fired with this admitted probability.
    Hazard {
        /// Probability used for the deterministic opportunity decision.
        probability_millionths: u32,
    },
    /// One typed event produced an impulse.
    Impulse {
        /// Exact typed event value.
        event: SignalValue,
    },
    /// One registered adapter transition was requested.
    StateTransition {
        /// Closed transition table identity.
        transition_table: FaultObjectId,
        /// Typed event or enum request.
        request: SignalValue,
        /// Exhaustively resolved adapter transition, possibly explorer-selected.
        selected_transition: FaultObjectId,
    },
    /// A registered time-varying service model received canonical inputs.
    ServiceProfile {
        /// Closed service-profile identity.
        service_profile: FaultObjectId,
        /// Exact named physical contract paired with every canonical input value.
        input_contracts: Vec<ServiceProfileInput>,
        /// Canonically signal-ID-ordered numeric inputs.
        inputs: Vec<SignalValue>,
    },
}

/// One named physical input to a service-profile mapping.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceProfileInput {
    /// Stable effect-specific role such as `distance` or `orientation`.
    pub role: FaultObjectId,
    /// Exact physical representation accepted for the role.
    pub shape: SignalShape,
}

/// One versioned exhaustive adapter state-transition table declaration.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct StateTransitionTableDeclaration {
    /// Stable table identity.
    pub id: FaultObjectId,
    /// Exact declaration semantic version.
    pub semantic_version: u16,
    /// Required event or enum input schema.
    pub input: SignalValueType,
    /// Exact owning effect family.
    pub effect: EffectKind,
    /// Exhaustive finite request-to-adapter-transition table.
    #[serde(serialize_with = "serialize_transition_map")]
    pub transitions: BTreeMap<SignalValue, FaultObjectId>,
    /// Mandatory transition for every request not present in `transitions`.
    pub default_transition: FaultObjectId,
}

fn serialize_transition_map<S>(
    transitions: &BTreeMap<SignalValue, FaultObjectId>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;

    let mut sequence = serializer.serialize_seq(Some(transitions.len()))?;
    for transition in transitions {
        sequence.serialize_element(&transition)?;
    }
    sequence.end()
}

/// One versioned time-varying service-profile declaration.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceProfileDeclaration {
    /// Stable profile identity.
    pub id: FaultObjectId,
    /// Exact declaration semantic version.
    pub semantic_version: u16,
    /// Exact owning effect family.
    pub effect: EffectKind,
    /// Canonical signal-ID-ordered named input contracts.
    pub inputs: Vec<ServiceProfileInput>,
    /// Dynamic effect fields produced by the profile.
    pub parameters: Vec<MappedEffectParameter>,
}

/// Closed declarations referenced by binding mappings.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BindingMappingRegistry {
    transition_tables: BTreeMap<FaultObjectId, StateTransitionTableDeclaration>,
    service_profiles: BTreeMap<FaultObjectId, ServiceProfileDeclaration>,
}

impl BindingMappingRegistry {
    /// Validates and canonicalizes every named mapping declaration.
    ///
    /// # Errors
    ///
    /// Returns [`BindingError`] for duplicate IDs, unsupported versions,
    /// empty/noncanonical transition sets, or malformed service profiles.
    pub fn new(
        transition_tables: Vec<StateTransitionTableDeclaration>,
        service_profiles: Vec<ServiceProfileDeclaration>,
    ) -> Result<Self, BindingError> {
        if transition_tables.len() > HARD_MAPPING_DECLARATIONS
            || service_profiles.len() > HARD_MAPPING_DECLARATIONS
        {
            return Err(BindingError::InvalidMappingRegistry);
        }
        let mut tables = BTreeMap::new();
        for declaration in transition_tables {
            if declaration.semantic_version != 1
                || !matches!(
                    declaration.input,
                    SignalValueType::Event(_) | SignalValueType::Enum(_)
                )
                || declaration.transitions.is_empty()
                || declaration.transitions.len() > HARD_SEARCH_CANDIDATE_LIMIT
                || declaration
                    .transitions
                    .keys()
                    .any(|request| request.value_type() != Some(declaration.input.clone()))
                || !declaration
                    .effect
                    .descriptor()
                    .lifetimes
                    .iter()
                    .any(|lifetime| {
                        matches!(
                            lifetime,
                            EffectLifetime::Impulse | EffectLifetime::StateMachine
                        )
                    })
                || tables.insert(declaration.id.clone(), declaration).is_some()
            {
                return Err(BindingError::InvalidMappingRegistry);
            }
        }
        let mut profiles = BTreeMap::new();
        for mut declaration in service_profiles {
            declaration.parameters.sort();
            if declaration.semantic_version != 1
                || declaration.inputs.is_empty()
                || declaration.inputs.len() > HARD_BINDING_SIGNAL_INPUT_LIMIT
                || declaration.parameters.is_empty()
                || declaration.parameters.len() > HARD_BINDING_SIGNAL_INPUT_LIMIT
                || declaration
                    .parameters
                    .windows(2)
                    .any(|pair| pair[0] == pair[1])
                || declaration
                    .inputs
                    .iter()
                    .any(|input| !input.shape.value_type.is_numeric())
                || declaration
                    .inputs
                    .iter()
                    .map(|input| &input.role)
                    .collect::<BTreeSet<_>>()
                    .len()
                    != declaration.inputs.len()
                || declaration
                    .parameters
                    .iter()
                    .any(|parameter| !parameter.belongs_to(declaration.effect))
                || profiles
                    .insert(declaration.id.clone(), declaration)
                    .is_some()
            {
                return Err(BindingError::InvalidMappingRegistry);
            }
        }
        Ok(Self {
            transition_tables: tables,
            service_profiles: profiles,
        })
    }

    fn validate_mapping(
        &self,
        mapping: &BindingMapping,
        shapes: &[&SignalShape],
        effect: EffectKind,
    ) -> Result<(), BindingError> {
        match mapping {
            BindingMapping::StateTransition { transition_table } => {
                let declaration = self
                    .transition_tables
                    .get(transition_table)
                    .ok_or(BindingError::UnknownMappingDeclaration)?;
                if shapes.len() != 1
                    || shapes[0].value_type != declaration.input
                    || declaration.effect != effect
                {
                    return Err(BindingError::InvalidMappingRegistry);
                }
            }
            BindingMapping::ServiceProfile { service_profile } => {
                let declaration = self
                    .service_profiles
                    .get(service_profile)
                    .ok_or(BindingError::UnknownMappingDeclaration)?;
                if declaration.effect != effect
                    || shapes.len() != declaration.inputs.len()
                    || shapes
                        .iter()
                        .zip(&declaration.inputs)
                        .any(|(actual, expected)| *actual != &expected.shape)
                {
                    return Err(BindingError::InvalidMappingRegistry);
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// Typed predicate for matching adapter opportunities.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpportunityFilter {
    /// Owning adapter.
    pub adapter: FaultAdapter,
    /// Nonempty canonical operation set.
    pub operations: OperationSet,
    /// Nonempty allowed phases.
    pub phases: BTreeSet<FaultPhase>,
    /// Optional target-kind restriction.
    pub target_kinds: BTreeSet<FaultTargetKind>,
}

impl OpportunityFilter {
    fn validate(&self, effect: EffectKind) -> Result<(), BindingError> {
        let descriptor = effect.descriptor();
        if self.operations.adapter() != self.adapter
            || self.phases.is_empty()
            || descriptor.adapter != self.adapter
            || self
                .phases
                .iter()
                .any(|phase| !descriptor.phases.contains(phase))
            || self
                .target_kinds
                .iter()
                .any(|kind| !descriptor.targets.contains(kind))
        {
            return Err(BindingError::InvalidOpportunityFilter);
        }
        Ok(())
    }

    /// Returns whether an opportunity satisfies every typed predicate.
    #[must_use]
    pub fn matches(&self, opportunity: &FaultOpportunity) -> bool {
        self.adapter == opportunity.adapter()
            && self.operations.contains(opportunity.operation())
            && self.phases.contains(&opportunity.phase())
            && (self.target_kinds.is_empty()
                || self.target_kinds.contains(&opportunity.target().kind()))
    }
}

/// Bounded search behavior for one binding.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum BindingSearchPolicy {
    /// Always uses the model result.
    Fixed,
    /// Branches fired/not-fired at selected opportunities.
    BranchOutcome {
        /// Maximum retained branches.
        maximum_branches: PositiveU64,
    },
    /// Branches among finite transition candidates.
    BranchTransition {
        /// Canonical transition identities.
        candidates: Vec<FaultObjectId>,
    },
    /// Branches among finite typed parameter values.
    BranchParameter {
        /// Dynamic destination field.
        parameter: MappedEffectParameter,
        /// Canonical candidate values.
        candidates: Vec<SignalValue>,
    },
    /// Mutates a bounded normalized-trace interval.
    MutateTraceWindow {
        /// First included virtual nanosecond.
        start_nanos: u64,
        /// Exclusive end virtual nanosecond.
        end_nanos: u64,
        /// Maximum changed samples.
        maximum_mutations: PositiveU64,
    },
    /// Mutates finite transfer-function points.
    MutateMapping {
        /// Canonical point indices.
        point_indices: Vec<u32>,
        /// Maximum changed points.
        maximum_mutations: PositiveU64,
    },
}

impl BindingSearchPolicy {
    /// Returns the largest finite candidate set admitted by this policy.
    #[must_use]
    pub fn candidate_count(&self) -> usize {
        match self {
            Self::BranchTransition { candidates } => candidates.len(),
            Self::BranchParameter { candidates, .. } => candidates.len(),
            Self::MutateMapping { point_indices, .. } => point_indices.len(),
            Self::Fixed | Self::BranchOutcome { .. } | Self::MutateTraceWindow { .. } => 0,
        }
    }

    /// Returns the maximum trace windows retained by this policy.
    #[must_use]
    pub const fn trace_mutation_windows(&self) -> u64 {
        if matches!(self, Self::MutateTraceWindow { .. }) {
            1
        } else {
            0
        }
    }

    /// Returns the maximum mapping points mutated by this policy.
    #[must_use]
    pub const fn mapping_mutation_points(&self) -> u64 {
        match self {
            Self::MutateMapping {
                maximum_mutations, ..
            } => maximum_mutations.get(),
            _ => 0,
        }
    }

    fn validate(
        &mut self,
        mapping: &BindingMapping,
        signals: &[SignalId],
        program: &SignalProgram,
    ) -> Result<(), BindingError> {
        match self {
            Self::Fixed => Ok(()),
            Self::BranchOutcome { maximum_branches }
                if matches!(mapping, BindingMapping::Hazard)
                    && maximum_branches.get() <= HARD_SEARCH_CHOICES_PER_STATE =>
            {
                Ok(())
            }
            Self::BranchOutcome { .. } => Err(BindingError::InvalidSearchPolicy),
            Self::BranchTransition { candidates } => {
                if !matches!(mapping, BindingMapping::StateTransition { .. }) {
                    return Err(BindingError::InvalidSearchPolicy);
                }
                candidates.sort();
                validate_candidates(candidates)
            }
            Self::BranchParameter {
                parameter,
                candidates,
            } => {
                let mapped = match mapping {
                    BindingMapping::MapParameter { parameter }
                    | BindingMapping::PiecewiseParameter { parameter, .. } => parameter,
                    _ => return Err(BindingError::InvalidSearchPolicy),
                };
                if parameter != mapped
                    || candidates
                        .iter()
                        .any(|value| !parameter.accepts_value(value))
                {
                    return Err(BindingError::InvalidSearchPolicy);
                }
                candidates.sort();
                validate_candidates(candidates)
            }
            Self::MutateTraceWindow {
                start_nanos,
                end_nanos,
                maximum_mutations,
            } => {
                let trace_input = signals.iter().any(|signal| {
                    program.nodes().iter().any(|node| {
                        &node.id == signal
                            && matches!(
                                node.kind,
                                SignalNodeKind::Source(SignalSourceSpecification::Trace { .. })
                            )
                    })
                });
                if *start_nanos >= *end_nanos
                    || maximum_mutations.get() > HARD_SEARCH_CHOICES_PER_STATE
                    || !trace_input
                {
                    Err(BindingError::InvalidSearchPolicy)
                } else {
                    Ok(())
                }
            }
            Self::MutateMapping {
                point_indices,
                maximum_mutations,
            } => {
                let point_count = match mapping {
                    BindingMapping::PiecewiseParameter { points, .. } => points.len(),
                    _ => return Err(BindingError::InvalidSearchPolicy),
                };
                point_indices.sort_unstable();
                validate_candidates(point_indices)?;
                if point_indices
                    .iter()
                    .any(|index| usize::try_from(*index).map_or(true, |index| index >= point_count))
                    || usize::try_from(maximum_mutations.get())
                        .map_or(true, |maximum| maximum > point_indices.len())
                {
                    return Err(BindingError::InvalidSearchPolicy);
                }
                Ok(())
            }
        }
    }
}

fn validate_candidates<T: PartialEq>(values: &[T]) -> Result<(), BindingError> {
    if values.is_empty()
        || values.len() > HARD_SEARCH_CANDIDATE_LIMIT
        || values.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(BindingError::InvalidSearchPolicy);
    }
    Ok(())
}

/// Sampling-event retention policy.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum SampleObservation {
    /// Records every sample.
    EverySample,
    /// Records changes and effect-relevant samples.
    ChangesAndEffects,
    /// Also records every Nth unchanged sample.
    EveryNth {
        /// Positive unchanged-sample stride.
        stride: PositiveU64,
    },
}

/// Stable observability choices for one binding.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct BindingObservabilityPolicy {
    /// Signal-sample retention.
    pub samples: SampleObservation,
    /// Whether inactive opportunities are recorded.
    pub record_inactive_opportunities: bool,
    /// Whether mapped values accompany their digest.
    pub retain_mapped_values: bool,
}

impl Default for BindingObservabilityPolicy {
    fn default() -> Self {
        Self {
            samples: SampleObservation::ChangesAndEffects,
            record_inactive_opportunities: false,
            retain_mapped_values: true,
        }
    }
}

/// One fully admitted signal-to-effect binding.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct FaultBinding {
    id: FaultObjectId,
    program: ContentHash,
    signals: Vec<SignalId>,
    sampling: BindingSampling,
    mapping: BindingMapping,
    selector: TargetSelector,
    phases: BTreeSet<FaultPhase>,
    effect: EffectRequest,
    opportunity_filter: Option<OpportunityFilter>,
    search: BindingSearchPolicy,
    observability: BindingObservabilityPolicy,
    transition_declaration: Option<StateTransitionTableDeclaration>,
    service_declaration: Option<ServiceProfileDeclaration>,
}

impl FaultBinding {
    /// Validates a binding that references no named mapping declarations.
    ///
    /// Use [`Self::new_with_registry`] for `state_transition` and
    /// `service_profile` mappings.
    ///
    /// # Errors
    ///
    /// Returns [`BindingError`] under the same conditions as
    /// [`Self::new_with_registry`]. Named mappings fail closed because the
    /// implicit registry is empty.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: FaultObjectId,
        signals: Vec<SignalId>,
        sampling: BindingSampling,
        mapping: BindingMapping,
        selector: TargetSelector,
        phases: BTreeSet<FaultPhase>,
        effect: EffectRequest,
        opportunity_filter: Option<OpportunityFilter>,
        search: BindingSearchPolicy,
        observability: BindingObservabilityPolicy,
        program: &SignalProgram,
    ) -> Result<Self, BindingError> {
        Self::new_with_registry(
            id,
            signals,
            sampling,
            mapping,
            selector,
            phases,
            effect,
            opportunity_filter,
            search,
            observability,
            program,
            &BindingMappingRegistry::default(),
        )
    }

    /// Validates a binding against one canonical signal program.
    ///
    /// # Errors
    ///
    /// Returns [`BindingError`] for an unexported input, incompatible shape,
    /// illegal target, missing filter, or unbounded search policy.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_registry(
        id: FaultObjectId,
        mut signals: Vec<SignalId>,
        sampling: BindingSampling,
        mapping: BindingMapping,
        selector: TargetSelector,
        phases: BTreeSet<FaultPhase>,
        effect: EffectRequest,
        opportunity_filter: Option<OpportunityFilter>,
        mut search: BindingSearchPolicy,
        observability: BindingObservabilityPolicy,
        program: &SignalProgram,
        mapping_registry: &BindingMappingRegistry,
    ) -> Result<Self, BindingError> {
        if signals.is_empty() {
            return Err(BindingError::NoSignals);
        }
        if signals.len() > HARD_BINDING_SIGNAL_INPUT_LIMIT {
            return Err(BindingError::TooManySignals);
        }
        signals.sort();
        if signals.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(BindingError::DuplicateSignal);
        }
        let shapes = signals
            .iter()
            .map(|signal| {
                program
                    .exported_shape(signal)
                    .ok_or_else(|| BindingError::MissingSignal(signal.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let opportunity_sampling = sampling == BindingSampling::AtOpportunity
            || matches!(
                &sampling,
                BindingSampling::AtEvent(parent) if parent.requires_opportunity()
            );
        if signals.iter().any(|signal| {
            program.exported_node(signal).is_some_and(|node| {
                (matches!(
                    node.domain,
                    SignalDomain::Operation | SignalDomain::State | SignalDomain::NodeCounter
                ) && !opportunity_sampling)
                    || (node.domain == SignalDomain::Event
                        && !matches!(&sampling, BindingSampling::AtEvent(_)))
                    || node.domain == SignalDomain::Spatial
            })
        }) || matches!(&sampling, BindingSampling::AtEvent(_))
            && !signals.iter().all(|signal| {
                program
                    .exported_node(signal)
                    .is_some_and(|node| node.domain == SignalDomain::Event)
            })
        {
            return Err(BindingError::InvalidSignalDomain);
        }
        validate_mapping(&mapping, &shapes, effect.kind(), effect.lifetime())?;
        mapping_registry.validate_mapping(&mapping, &shapes, effect.kind())?;
        let transition_declaration = match &mapping {
            BindingMapping::StateTransition { transition_table } => mapping_registry
                .transition_tables
                .get(transition_table)
                .cloned(),
            _ => None,
        };
        let service_declaration = match &mapping {
            BindingMapping::ServiceProfile { service_profile } => mapping_registry
                .service_profiles
                .get(service_profile)
                .cloned(),
            _ => None,
        };
        if let (BindingSearchPolicy::BranchTransition { candidates }, Some(declaration)) =
            (&search, &transition_declaration)
            && candidates.iter().any(|candidate| {
                candidate != &declaration.default_transition
                    && !declaration
                        .transitions
                        .values()
                        .any(|transition| transition == candidate)
            })
        {
            return Err(BindingError::InvalidSearchPolicy);
        }
        if phases.is_empty()
            || phases
                .iter()
                .any(|phase| !effect.kind().descriptor().phases.contains(phase))
        {
            return Err(BindingError::InvalidBindingPhases);
        }
        if opportunity_sampling && effect.lifetime() == EffectLifetime::Persistent {
            return Err(BindingError::PersistentOpportunitySampling);
        }
        if let BindingMapping::Threshold {
            comparison,
            threshold,
            clear_threshold: Some(clear_threshold),
            residence_nanos,
        } = &mapping
        {
            let ordering = compare_numeric(threshold, clear_threshold)
                .map_err(|_| BindingError::InvalidHysteresis)?;
            let valid_deadband = match comparison {
                ThresholdComparison::LessThan | ThresholdComparison::LessThanOrEqual => {
                    ordering.is_lt()
                }
                ThresholdComparison::GreaterThan | ThresholdComparison::GreaterThanOrEqual => {
                    ordering.is_gt()
                }
            };
            if !valid_deadband || (sampling == BindingSampling::AtChange && *residence_nanos > 0) {
                return Err(BindingError::InvalidHysteresis);
            }
        }
        if matches!(
            mapping,
            BindingMapping::Threshold {
                residence_nanos: 1..,
                ..
            }
        ) && sampling == BindingSampling::AtChange
        {
            return Err(BindingError::InvalidHysteresis);
        }
        selector.validate()?;
        for target in selector.resolved().targets() {
            if !effect.kind().descriptor().targets.contains(&target.kind()) {
                return Err(BindingError::EffectTarget {
                    effect: effect.kind(),
                    target: target.kind(),
                });
            }
        }
        if selector
            .resolved()
            .adapter()
            .is_some_and(|adapter| adapter != effect.kind().descriptor().adapter)
        {
            return Err(BindingError::EffectAdapter);
        }
        if matches!(selector, TargetSelector::DynamicPath { .. })
            && effect.kind().descriptor().adapter != FaultAdapter::Network
        {
            return Err(BindingError::DynamicSelectorAdapter);
        }
        match (opportunity_sampling, opportunity_filter.is_some()) {
            (true, false) => return Err(BindingError::MissingOpportunityFilter),
            (false, true) => return Err(BindingError::UnexpectedOpportunityFilter),
            _ => {}
        }
        if matches!(mapping, BindingMapping::Hazard) && !opportunity_sampling {
            return Err(BindingError::HazardSampling);
        }
        if let Some(filter) = &opportunity_filter {
            filter.validate(effect.kind())?;
            if filter.phases != phases {
                return Err(BindingError::InvalidBindingPhases);
            }
        }
        search.validate(&mapping, &signals, program)?;
        Ok(Self {
            id,
            program: program.id(),
            signals,
            sampling,
            mapping,
            selector,
            phases,
            effect,
            opportunity_filter,
            search,
            observability,
            transition_declaration,
            service_declaration,
        })
    }

    /// Returns the stable binding identity.
    #[must_use]
    pub const fn id(&self) -> &FaultObjectId {
        &self.id
    }

    /// Returns the exact signal program against which this binding was admitted.
    #[must_use]
    pub const fn program(&self) -> ContentHash {
        self.program
    }

    /// Returns canonical input signal IDs.
    #[must_use]
    pub fn signals(&self) -> &[SignalId] {
        &self.signals
    }

    /// Returns the sampling rule.
    #[must_use]
    pub const fn sampling(&self) -> &BindingSampling {
        &self.sampling
    }

    /// Returns the mapping rule.
    #[must_use]
    pub const fn mapping(&self) -> &BindingMapping {
        &self.mapping
    }

    /// Returns the selector.
    #[must_use]
    pub const fn selector(&self) -> &TargetSelector {
        &self.selector
    }

    /// Returns the nonempty canonical adapter phases authored for this binding.
    #[must_use]
    pub const fn phases(&self) -> &BTreeSet<FaultPhase> {
        &self.phases
    }

    /// Returns the typed effect request.
    #[must_use]
    pub const fn effect(&self) -> &EffectRequest {
        &self.effect
    }

    /// Returns the optional opportunity filter.
    #[must_use]
    pub const fn opportunity_filter(&self) -> Option<&OpportunityFilter> {
        self.opportunity_filter.as_ref()
    }

    /// Returns the bounded search policy.
    #[must_use]
    pub const fn search(&self) -> &BindingSearchPolicy {
        &self.search
    }

    /// Returns the event-retention policy.
    #[must_use]
    pub const fn observability(&self) -> BindingObservabilityPolicy {
        self.observability
    }

    /// Returns the admitted exhaustive state-transition declaration.
    #[must_use]
    pub const fn transition_declaration(&self) -> Option<&StateTransitionTableDeclaration> {
        self.transition_declaration.as_ref()
    }

    /// Returns the admitted service-profile declaration.
    #[must_use]
    pub const fn service_declaration(&self) -> Option<&ServiceProfileDeclaration> {
        self.service_declaration.as_ref()
    }

    /// Encodes and hashes every executable field using the versioned wire form.
    pub(crate) fn contract_digest(&self) -> Result<ContentHash, serde_json::Error> {
        let mut material = b"crucible.fault-binding-contract.json.v1\0".to_vec();
        material.extend_from_slice(&serde_json::to_vec(self)?);
        Ok(ContentHash::from_bytes(&material))
    }

    pub(crate) fn materialize_fixed(
        &self,
        program: &SignalProgram,
        mapping: BindingMapping,
    ) -> Result<Self, BindingError> {
        let registry = BindingMappingRegistry::new(
            self.transition_declaration.clone().into_iter().collect(),
            self.service_declaration.clone().into_iter().collect(),
        )?;
        Self::new_with_registry(
            self.id.clone(),
            self.signals.clone(),
            self.sampling.clone(),
            mapping,
            self.selector.clone(),
            self.phases.clone(),
            self.effect.clone(),
            self.opportunity_filter.clone(),
            BindingSearchPolicy::Fixed,
            self.observability,
            program,
            &registry,
        )
    }
}

fn validate_mapping(
    mapping: &BindingMapping,
    shapes: &[&SignalShape],
    effect: EffectKind,
    lifetime: EffectLifetime,
) -> Result<(), BindingError> {
    let exactly_one = || {
        shapes
            .first()
            .filter(|_| shapes.len() == 1)
            .copied()
            .ok_or(BindingError::MappingArity)
    };
    match mapping {
        BindingMapping::ActiveWhenTrue { .. } => {
            let shape = exactly_one()?;
            if shape.value_type != SignalValueType::Bool || lifetime != EffectLifetime::Persistent {
                return Err(BindingError::MappingShape);
            }
        }
        BindingMapping::ActiveWhenEqual { .. } => {
            let shape = exactly_one()?;
            if !matches!(shape.value_type, SignalValueType::Enum(_))
                || lifetime != EffectLifetime::Persistent
            {
                return Err(BindingError::MappingShape);
            }
        }
        BindingMapping::Threshold {
            threshold,
            clear_threshold,
            ..
        } => {
            let shape = exactly_one()?;
            if !shape.value_type.is_numeric()
                || threshold.value_type().as_ref() != Some(&shape.value_type)
                || clear_threshold
                    .as_ref()
                    .is_some_and(|value| value.value_type().as_ref() != Some(&shape.value_type))
                || lifetime != EffectLifetime::Persistent
            {
                return Err(BindingError::MappingShape);
            }
        }
        BindingMapping::MapParameter { parameter } => {
            if !parameter.accepts(exactly_one()?) || !parameter.belongs_to(effect) {
                return Err(BindingError::MappingShape);
            }
        }
        BindingMapping::PiecewiseParameter {
            parameter, points, ..
        } => {
            let input = exactly_one()?;
            if points.len() < 2
                || points.len() > HARD_SEARCH_CANDIDATE_LIMIT
                || points.windows(2).any(|pair| pair[0].input >= pair[1].input)
                || points
                    .iter()
                    .any(|point| point.input.value_type().as_ref() != Some(&input.value_type))
            {
                return Err(BindingError::InvalidPiecewiseMapping);
            }
            let output_type = points[0]
                .output
                .value_type()
                .ok_or(BindingError::MappingShape)?;
            let output_shape = SignalShape {
                value_type: output_type.clone(),
                unit: input.unit,
                scale_decimal_exponent: input.scale_decimal_exponent,
            };
            if points
                .iter()
                .any(|point| point.output.value_type() != Some(output_type.clone()))
                || !parameter.accepts(&output_shape)
                || !parameter.belongs_to(effect)
            {
                return Err(BindingError::MappingShape);
            }
        }
        BindingMapping::Hazard => {
            if !MappedEffectParameter::Probability.accepts(exactly_one()?)
                || lifetime != EffectLifetime::Opportunity
            {
                return Err(BindingError::MappingShape);
            }
        }
        BindingMapping::ImpulseOnEvent => {
            if !matches!(exactly_one()?.value_type, SignalValueType::Event(_))
                || lifetime != EffectLifetime::Impulse
            {
                return Err(BindingError::MappingShape);
            }
        }
        BindingMapping::StateTransition { .. } => {
            if !matches!(
                exactly_one()?.value_type,
                SignalValueType::Event(_) | SignalValueType::Enum(_)
            ) || !matches!(
                lifetime,
                EffectLifetime::Impulse | EffectLifetime::StateMachine
            ) {
                return Err(BindingError::MappingShape);
            }
        }
        BindingMapping::ServiceProfile { .. } => {
            if shapes.is_empty() || shapes.iter().any(|shape| !shape.value_type.is_numeric()) {
                return Err(BindingError::MappingShape);
            }
        }
    }
    Ok(())
}

/// Admission failure for a signal-to-effect binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindingError {
    /// Selector unexpectedly resolved no targets.
    EmptySelector,
    /// Selector exceeded the hard target limit.
    TooManyTargets {
        /// Resolved target count.
        actual: usize,
        /// Compiled maximum target count.
        hard: usize,
    },
    /// Resolved target was malformed.
    Target(FaultContractError),
    /// Selector contains the same target twice.
    DuplicateTarget,
    /// Selector crosses adapter domains.
    MixedTargetAdapters,
    /// Exact selector did not resolve exactly one target.
    ExactSelectorCardinality,
    /// Dynamic selector semantic version is unsupported.
    SelectorVersion {
        /// Unsupported semantic version.
        actual: u16,
    },
    /// Dynamic path contains non-network targets.
    DynamicSelectorAdapter,
    /// Binding has no signal inputs.
    NoSignals,
    /// Binding exceeds the input limit.
    TooManySignals,
    /// Binding contains a duplicate input.
    DuplicateSignal,
    /// Input does not name an exported output.
    MissingSignal(SignalId),
    /// Mapping has the wrong input count.
    MappingArity,
    /// Mapping type, unit, or lifetime is incompatible.
    MappingShape,
    /// Piecewise mapping is malformed or unbounded.
    InvalidPiecewiseMapping,
    /// Effect cannot apply to a selected target.
    EffectTarget {
        /// Requested effect kind.
        effect: EffectKind,
        /// Rejected target kind.
        target: FaultTargetKind,
    },
    /// Selector and effect use different adapters.
    EffectAdapter,
    /// Binding phase set is empty or outside the effect registry contract.
    InvalidBindingPhases,
    /// Per-opportunity sampling lacks a filter.
    MissingOpportunityFilter,
    /// Non-opportunity sampling supplied an unusable opportunity filter.
    UnexpectedOpportunityFilter,
    /// A keyed hazard was not configured for per-opportunity sampling.
    HazardSampling,
    /// A persistent effect cannot use operation-triggered global binding state.
    PersistentOpportunitySampling,
    /// Threshold deadband ordering or residence sampling is invalid.
    InvalidHysteresis,
    /// A signal domain cannot be projected at the selected sampling boundary.
    InvalidSignalDomain,
    /// Opportunity filter contradicts the registry.
    InvalidOpportunityFilter,
    /// Search candidates or mutation bounds are invalid.
    InvalidSearchPolicy,
    /// A named state-transition table or service profile is absent.
    UnknownMappingDeclaration,
    /// A mapping declaration is malformed or incompatible with its binding.
    InvalidMappingRegistry,
}

impl fmt::Display for BindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid fault binding: {self:?}")
    }
}

impl Error for BindingError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn object_id(value: &str) -> FaultObjectId {
        match FaultObjectId::parse(value) {
            Ok(id) => id,
            Err(error) => panic!("test object ID must be valid: {error}"),
        }
    }

    fn signal_id(value: &str) -> SignalId {
        match SignalId::parse(value) {
            Ok(id) => id,
            Err(error) => panic!("test signal ID must be valid: {error}"),
        }
    }

    fn boolean_program() -> SignalProgram {
        let id = signal_id("active");
        let shape = match SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0) {
            Ok(value) => value,
            Err(error) => panic!("test shape must be valid: {error}"),
        };
        match SignalProgram::new(
            vec![SignalNode {
                id: id.clone(),
                domain: SignalDomain::VirtualTime,
                output: shape,
                inputs: Vec::new(),
                kind: SignalNodeKind::Constant {
                    value: SignalValue::Bool(true),
                },
            }],
            vec![id],
            SignalResourceLimits::default(),
        ) {
            Ok(value) => value,
            Err(error) => panic!("test program must be valid: {error}"),
        }
    }

    #[test]
    fn selectors_are_canonical_and_homogeneous() {
        let first = ResolvedFaultTarget::Node {
            node: object_id("node-a"),
        };
        let second = ResolvedFaultTarget::Node {
            node: object_id("node-b"),
        };
        let set = match ResolvedTargetSet::new(vec![second.clone(), first.clone()], false) {
            Ok(value) => value,
            Err(error) => panic!("test selector must be valid: {error}"),
        };
        assert_eq!(set.targets(), &[first, second]);

        let network = ResolvedFaultTarget::NetworkForwarder {
            forwarder: object_id("switch-a"),
        };
        assert!(ResolvedTargetSet::new(vec![network, set.targets()[0].clone()], false).is_err());
    }

    #[test]
    fn search_candidates_are_finite_unique_and_canonical() {
        let mut candidates = vec![object_id("transition-b"), object_id("transition-a")];
        candidates.sort();
        assert!(validate_candidates(&candidates).is_ok());
        assert_eq!(
            candidates,
            vec![object_id("transition-a"), object_id("transition-b")]
        );
        assert!(validate_candidates(&[SignalValue::U64(1), SignalValue::U64(1)]).is_err());
    }

    #[test]
    fn empty_dynamic_path_cannot_hide_a_storage_effect() {
        let targets = match ResolvedTargetSet::new(Vec::new(), true) {
            Ok(value) => value,
            Err(error) => panic!("explicit empty selector must be valid: {error}"),
        };
        let effect = match EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Persistent,
            EffectSpecification::Storage(StorageEffectSpecification::Availability {
                state: StorageAvailabilityState::Offline,
                reconnect_policy: StorageTransitionPolicy::Fail,
            }),
        ) {
            Ok(value) => value,
            Err(error) => panic!("test effect must be valid: {error}"),
        };
        let result = FaultBinding::new(
            object_id("bad-dynamic-path"),
            vec![signal_id("active")],
            BindingSampling::AtBoundary,
            BindingMapping::ActiveWhenTrue { invert: false },
            TargetSelector::DynamicPath {
                path: object_id("path-a"),
                initial: targets,
                membership_semantic_version: 1,
            },
            [FaultPhase::Admit].into_iter().collect(),
            effect,
            None,
            BindingSearchPolicy::Fixed,
            BindingObservabilityPolicy {
                samples: SampleObservation::ChangesAndEffects,
                record_inactive_opportunities: false,
                retain_mapped_values: false,
            },
            &boolean_program(),
        );
        assert_eq!(result, Err(BindingError::DynamicSelectorAdapter));
    }

    #[test]
    fn mapped_field_must_belong_to_the_effect() {
        let shape = SignalShape {
            value_type: SignalValueType::ProbabilityMillionths,
            unit: SignalUnit::ProbabilityMillionths,
            scale_decimal_exponent: 0,
        };
        assert_eq!(
            validate_mapping(
                &BindingMapping::MapParameter {
                    parameter: MappedEffectParameter::Probability,
                },
                &[&shape],
                EffectKind::NetworkAvailability,
                EffectLifetime::Persistent,
            ),
            Err(BindingError::MappingShape)
        );
    }

    #[test]
    fn binding_contract_codec_is_golden_and_covers_every_top_level_field() {
        let program = boolean_program();
        let target = ResolvedTargetSet::new(
            vec![ResolvedFaultTarget::NetworkSegment {
                segment: object_id("segment-a"),
                direction: FaultDirection::AToB,
            }],
            false,
        )
        .unwrap_or_else(|error| panic!("test target must be valid: {error}"));
        let effect = EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Persistent,
            EffectSpecification::Network(NetworkEffectSpecification::Availability {
                state: NetworkAvailabilityState::Down,
                queued_policy: NetworkInFlightPolicy::Drop,
                in_flight_policy: NetworkInFlightPolicy::Drop,
            }),
        )
        .unwrap_or_else(|error| panic!("test effect must be valid: {error}"));
        let binding = FaultBinding::new(
            object_id("binding-golden"),
            vec![signal_id("active")],
            BindingSampling::AtBoundary,
            BindingMapping::ActiveWhenTrue { invert: false },
            TargetSelector::Exact(target),
            [FaultPhase::Admit].into_iter().collect(),
            effect,
            None,
            BindingSearchPolicy::Fixed,
            BindingObservabilityPolicy {
                samples: SampleObservation::ChangesAndEffects,
                record_inactive_opportunities: false,
                retain_mapped_values: false,
            },
            &program,
        )
        .unwrap_or_else(|error| panic!("test binding must be valid: {error}"));
        let golden = binding
            .contract_digest()
            .unwrap_or_else(|error| panic!("binding encoding must succeed: {error}"));
        assert_eq!(
            golden.to_hex(),
            "c72f522b8fc2e39d01f57a1547765eb7a5062545a33482e5940b778bd73e2d09"
        );

        let mut mutations = Vec::new();
        let mut changed = binding.clone();
        changed.id = object_id("binding-changed");
        mutations.push(changed);
        let mut changed = binding.clone();
        changed.program = ContentHash::from_bytes(b"changed-program");
        mutations.push(changed);
        let mut changed = binding.clone();
        changed.signals.push(signal_id("other-signal"));
        mutations.push(changed);
        let mut changed = binding.clone();
        changed.sampling = BindingSampling::AtChange;
        mutations.push(changed);
        let mut changed = binding.clone();
        changed.mapping = BindingMapping::ActiveWhenTrue { invert: true };
        mutations.push(changed);
        let mut changed = binding.clone();
        changed.selector = TargetSelector::TargetSet(changed.selector.resolved().clone());
        mutations.push(changed);
        let mut changed = binding.clone();
        changed.phases.insert(FaultPhase::Resolve);
        mutations.push(changed);
        let mut changed = binding.clone();
        changed.effect = EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Persistent,
            EffectSpecification::Network(NetworkEffectSpecification::Availability {
                state: NetworkAvailabilityState::ReceiveOnly,
                queued_policy: NetworkInFlightPolicy::Drop,
                in_flight_policy: NetworkInFlightPolicy::Drop,
            }),
        )
        .unwrap_or_else(|error| panic!("changed effect must be valid: {error}"));
        mutations.push(changed);
        let mut changed = binding.clone();
        changed.opportunity_filter = Some(OpportunityFilter {
            adapter: FaultAdapter::Network,
            operations: OperationSet::new(vec![FaultOperation::NetworkTransmit])
                .unwrap_or_else(|error| panic!("operation set must be valid: {error}")),
            phases: [FaultPhase::Admit].into_iter().collect(),
            target_kinds: BTreeSet::new(),
        });
        mutations.push(changed);
        let mut changed = binding.clone();
        changed.search = BindingSearchPolicy::BranchOutcome {
            maximum_branches: PositiveU64::new("maximum_branches", 2)
                .unwrap_or_else(|error| panic!("search bound must be valid: {error}")),
        };
        mutations.push(changed);
        let mut changed = binding.clone();
        changed.observability.record_inactive_opportunities = true;
        mutations.push(changed);
        let mut changed = binding.clone();
        changed.transition_declaration = Some(StateTransitionTableDeclaration {
            id: object_id("transition-table"),
            semantic_version: 1,
            input: SignalValueType::Event(signal_id("transition-request")),
            effect: EffectKind::NetworkAvailability,
            transitions: [(SignalValue::Bool(true), object_id("transition-a"))]
                .into_iter()
                .collect(),
            default_transition: object_id("transition-default"),
        });
        mutations.push(changed);
        let mut changed = binding.clone();
        changed.service_declaration = Some(ServiceProfileDeclaration {
            id: object_id("service-profile"),
            semantic_version: 1,
            effect: EffectKind::NetworkAvailability,
            inputs: vec![ServiceProfileInput {
                role: object_id("service-input"),
                shape: SignalShape::new(SignalValueType::U64, SignalUnit::Dimensionless, 0)
                    .unwrap_or_else(|error| panic!("service input must be valid: {error}")),
            }],
            parameters: vec![MappedEffectParameter::UnsignedCount],
        });
        mutations.push(changed);

        for changed in mutations {
            let changed_digest = changed
                .contract_digest()
                .unwrap_or_else(|error| panic!("changed binding must encode: {error}"));
            assert_ne!(changed_digest, golden);
        }
    }
}
