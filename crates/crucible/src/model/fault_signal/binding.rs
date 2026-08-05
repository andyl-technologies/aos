//! Validated bindings from signal outputs to typed production effects.
//!
//! Bindings are the only bridge between cause signals and adapter mutations.
//! Selectors, sampling, mapping, search, and observability are closed enums so
//! scenario data cannot invoke arbitrary adapter behavior.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use super::*;

/// Maximum concrete targets produced by one selector.
pub const HARD_BINDING_TARGET_LIMIT: usize = 65_536;
/// Maximum finite candidates in one search policy or transfer function.
pub const HARD_SEARCH_CANDIDATE_LIMIT: usize = 4_096;

/// When a binding samples its signal inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BindingSampling {
    /// Samples at scheduler boundaries.
    AtBoundary,
    /// Samples for each matching adapter opportunity.
    AtOpportunity,
    /// Samples whenever an input changes.
    AtChange,
    /// Samples on an exact positive virtual-time cadence.
    CadenceNanos(PositiveU64),
}

/// A finite, homogeneous, already-resolved selector result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedTargetSet {
    targets: Vec<ResolvedFaultTarget>,
    allow_empty: bool,
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

    fn accepts_value(self, value: &SignalValue) -> bool {
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
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BindingMapPoint {
    /// Strictly increasing input value.
    pub input: SignalValue,
    /// Corresponding output value.
    pub output: SignalValue,
}

/// Closed signal-to-effect mapping vocabulary.
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// Typed predicate for matching adapter opportunities.
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
    fn validate(
        &mut self,
        mapping: &BindingMapping,
        signals: &[SignalId],
        program: &SignalProgram,
    ) -> Result<(), BindingError> {
        match self {
            Self::Fixed => Ok(()),
            Self::BranchOutcome { .. } if matches!(mapping, BindingMapping::Hazard) => Ok(()),
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
                ..
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
                if *start_nanos >= *end_nanos || !trace_input {
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BindingObservabilityPolicy {
    /// Signal-sample retention.
    pub samples: SampleObservation,
    /// Whether inactive opportunities are recorded.
    pub record_inactive_opportunities: bool,
    /// Whether mapped values accompany their digest.
    pub retain_mapped_values: bool,
}

/// One fully admitted signal-to-effect binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultBinding {
    id: FaultObjectId,
    signals: Vec<SignalId>,
    sampling: BindingSampling,
    mapping: BindingMapping,
    selector: TargetSelector,
    effect: EffectRequest,
    opportunity_filter: Option<OpportunityFilter>,
    search: BindingSearchPolicy,
    observability: BindingObservabilityPolicy,
}

impl FaultBinding {
    /// Validates a binding against one canonical signal program.
    ///
    /// # Errors
    ///
    /// Returns [`BindingError`] for an unexported input, incompatible shape,
    /// illegal target, missing filter, or unbounded search policy.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: FaultObjectId,
        mut signals: Vec<SignalId>,
        sampling: BindingSampling,
        mapping: BindingMapping,
        selector: TargetSelector,
        effect: EffectRequest,
        opportunity_filter: Option<OpportunityFilter>,
        mut search: BindingSearchPolicy,
        observability: BindingObservabilityPolicy,
        program: &SignalProgram,
    ) -> Result<Self, BindingError> {
        if signals.is_empty() {
            return Err(BindingError::NoSignals);
        }
        if signals.len() > usize::from(HARD_SIGNAL_INPUTS_PER_NODE_LIMIT) {
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
        validate_mapping(&mapping, &shapes, effect.kind(), effect.lifetime())?;
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
        if (sampling == BindingSampling::AtOpportunity || matches!(mapping, BindingMapping::Hazard))
            && opportunity_filter.is_none()
        {
            return Err(BindingError::MissingOpportunityFilter);
        }
        if let Some(filter) = &opportunity_filter {
            filter.validate(effect.kind())?;
        }
        search.validate(&mapping, &signals, program)?;
        Ok(Self {
            id,
            signals,
            sampling,
            mapping,
            selector,
            effect,
            opportunity_filter,
            search,
            observability,
        })
    }

    /// Returns the stable binding identity.
    #[must_use]
    pub const fn id(&self) -> &FaultObjectId {
        &self.id
    }

    /// Returns canonical input signal IDs.
    #[must_use]
    pub fn signals(&self) -> &[SignalId] {
        &self.signals
    }

    /// Returns the sampling rule.
    #[must_use]
    pub const fn sampling(&self) -> BindingSampling {
        self.sampling
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
    /// Per-opportunity sampling lacks a filter.
    MissingOpportunityFilter,
    /// Opportunity filter contradicts the registry.
    InvalidOpportunityFilter,
    /// Search candidates or mutation bounds are invalid.
    InvalidSearchPolicy,
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
}
