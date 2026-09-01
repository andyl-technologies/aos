//! Validated bindings from signal outputs to typed production effects.
//!
//! Bindings are the only bridge between cause signals and adapter mutations.
//! Selectors, sampling, mapping, search, and observability are closed enums so
//! scenario data cannot invoke arbitrary adapter behavior.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use super::*;

#[path = "binding/mapping.rs"]
mod mapping;
pub use mapping::*;
#[path = "binding/search.rs"]
mod search;
pub use search::BindingSearchPolicy;
#[cfg(test)]
use search::validate_candidates;
#[path = "binding/contract.rs"]
mod contract;
pub use contract::FaultBinding;

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
