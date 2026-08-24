//! Scenario-owned measurement windows, metric contracts, and exact aggregation policy.
//!
//! Measurement definitions are immutable scenario input. They may name only
//! model-owned world, plan, and property identities or explicitly bounded
//! guest markers. Runtime samples and aggregates are separate observation
//! records and cannot modify these contracts.

use super::*;

/// Maximum measurement windows in one scenario.
pub const MAX_MEASUREMENT_DEFINITIONS: usize = 4_096;
/// Maximum metrics across every measurement window in one scenario.
pub const MAX_SCENARIO_METRICS: usize = 65_536;
/// Maximum metrics in one measurement window.
pub const MAX_METRICS_PER_MEASUREMENT: usize = 1_024;
/// Maximum nodes in one measurement cohort.
pub const MAX_MEASUREMENT_COHORT_NODES: usize = 4_096;
/// Maximum children in one compound boundary selector.
pub const MAX_MEASUREMENT_BOUNDARY_CHILDREN: usize = 64;
/// Maximum nesting depth in one compound boundary selector.
pub const MAX_MEASUREMENT_BOUNDARY_DEPTH: usize = 32;
/// Maximum variants in one enumerated metric type.
pub const MAX_METRIC_ENUM_VARIANTS: usize = 4_096;
/// Maximum elements in one bounded integer-vector metric value.
pub const MAX_METRIC_VECTOR_ELEMENTS: u32 = 65_536;
/// Maximum declared histogram boundaries in one metric.
pub const MAX_METRIC_HISTOGRAM_BOUNDS: usize = 4_096;
/// Maximum UTF-8 bytes in one measurement identifier.
pub const MAX_MEASUREMENT_IDENTIFIER_BYTES: usize = 128;
/// Maximum aggregate canonical bytes in one measurement-definition component.
pub const MAX_MEASUREMENT_DEFINITION_BYTES: usize = 32 * 1024 * 1024;
/// Closed semantic-unit registry for measurement-definition version 1.
pub const SUPPORTED_METRIC_UNITS: [&str; 10] = [
    "boolean",
    "bytes",
    "dimensionless",
    "events",
    "instructions",
    "operations",
    "packets",
    "ratio",
    "samples",
    "virtual_nanoseconds",
];

macro_rules! measurement_identifier {
    ($name:ident, $summary:literal) => {
        #[doc = $summary]
        #[derive(
            Clone,
            Debug,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            serde::Serialize,
            serde::Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Parses a canonical measurement identifier.
            ///
            /// # Errors
            ///
            /// Returns [`MeasurementDefinitionError::InvalidIdentifier`] when
            /// the value is empty, exceeds the byte limit, or contains bytes
            /// outside ASCII alphanumeric, `.`, `_`, `-`, `/`, and `:`.
            pub fn parse(value: impl Into<String>) -> Result<Self, MeasurementDefinitionError> {
                let value = value.into();
                validate_measurement_identifier(stringify!($name), &value)?;
                Ok(Self(value))
            }

            /// Returns the canonical identifier text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

measurement_identifier!(
    MeasurementId,
    "A stable scenario measurement-window identifier."
);
measurement_identifier!(
    MetricId,
    "A stable metric identifier within one measurement."
);
measurement_identifier!(
    UnitId,
    "A stable semantic unit identifier for one metric value."
);
measurement_identifier!(
    MeasurementInstanceKey,
    "A bounded semantic instance key carried by a dynamic guest marker."
);

/// A modeled timeout that can terminate one measurement window.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ModeledMeasurementTimeout {
    /// Timeout after a virtual-time duration.
    VirtualTime {
        /// Nonzero virtual duration in nanoseconds.
        nanos: u64,
    },
    /// Timeout after a node retires a bounded instruction count.
    NodeIcount {
        /// Node whose modeled instruction counter is observed.
        node: NodeId,
        /// Nonzero retired-instruction budget.
        instructions: u64,
    },
    /// Timeout after a plan event fires a bounded number of times.
    EventCount {
        /// Plan event whose firings are counted.
        event: EventId,
        /// Nonzero firing budget.
        count: u64,
    },
}

/// Canonical node-cohort satisfaction policy for one measurement.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum CohortPolicy {
    /// Every declared node must satisfy cohort-aware boundaries.
    All(Vec<NodeId>),
    /// The first node in canonical event order satisfies cohort-aware boundaries.
    Any(Vec<NodeId>),
    /// A declared minimum number of nodes must satisfy cohort-aware boundaries.
    Quorum {
        /// Canonical cohort membership.
        nodes: Vec<NodeId>,
        /// Nonzero required member count, no greater than `nodes.len()`.
        required: u32,
    },
}

/// One canonical modeled boundary used to open or close a measurement window.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BoundarySelector {
    /// The scenario genesis coordinate.
    ScenarioGenesis,
    /// The scenario's deterministic ready point.
    ScenarioReady,
    /// A declared plan event firing.
    PlanEvent {
        /// Event whose firing satisfies the boundary.
        event: EventId,
    },
    /// An opportunity emitted for a declared fault binding.
    FaultOpportunity {
        /// Stable fault-binding identity.
        binding: FaultObjectId,
    },
    /// A state transition emitted for a declared fault binding.
    FaultTransition {
        /// Stable fault-binding identity.
        binding: FaultObjectId,
    },
    /// An applied effect emitted for a declared fault binding.
    FaultApplied {
        /// Stable fault-binding identity.
        binding: FaultObjectId,
    },
    /// A bounded dynamic marker from the white-box guest channel.
    GuestMarker {
        /// Predeclared marker identity.
        marker: MarkerId,
        /// Optional semantic instance key.
        instance: Option<MeasurementInstanceKey>,
    },
    /// A terminal verdict for one declared property.
    PropertyVerdict {
        /// Property whose verdict satisfies the boundary.
        property: AssertionId,
    },
    /// One exact virtual-time coordinate.
    VirtualTime {
        /// Virtual-time coordinate.
        at: VirtualTime,
    },
    /// One exact node instruction-count coordinate.
    NodeIcount {
        /// Node whose modeled instruction count is observed.
        node: NodeId,
        /// Retired-instruction coordinate.
        instructions: u64,
    },
    /// The firing count of one declared plan event.
    EventCount {
        /// Declared plan event.
        event: EventId,
        /// Nonzero firing count.
        count: u64,
    },
    /// Scheduler quiescence with no modeled blockers.
    SchedulerQuiescence,
    /// A modeled network-idle interval.
    NetworkIdle {
        /// Optional exact link; `None` observes the whole declared network.
        link: Option<LinkId>,
        /// Nonzero idle duration.
        window: SimDuration,
    },
    /// Every child selector must hold at one canonical event boundary.
    All {
        /// Nonempty bounded child selectors.
        selectors: Vec<BoundarySelector>,
    },
    /// At least one child selector must hold; event order breaks simultaneous ties.
    Any {
        /// Nonempty bounded child selectors.
        selectors: Vec<BoundarySelector>,
    },
}

/// Canonical value type admitted for one metric.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MetricValueType {
    /// Signed 64-bit integer.
    SignedInteger,
    /// Unsigned 64-bit integer.
    UnsignedInteger,
    /// Reduced signed numerator and positive unsigned denominator.
    ReducedRational,
    /// Boolean value.
    Boolean,
    /// One value from a declared canonical identifier set.
    Enumerated {
        /// Nonempty canonical variant set.
        variants: Vec<String>,
    },
    /// A bounded vector of signed or unsigned 64-bit integers.
    IntegerVector {
        /// Whether elements use signed rather than unsigned interpretation.
        signed: bool,
        /// Nonzero maximum vector length.
        maximum_elements: u32,
    },
}

/// Canonical source of one metric's samples.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MetricSource {
    /// Type-checked samples from the white-box guest protocol.
    Guest,
    /// Host-derived virtual-time coordinates.
    VirtualTime,
    /// Host-derived instruction counts for one node.
    NodeIcount {
        /// Declared world node.
        node: NodeId,
    },
    /// Host-derived firing count for one plan event.
    ModeledEventCount {
        /// Declared plan event.
        event: EventId,
    },
    /// Host-derived modeled frame-drop count.
    NetworkModeledDropCount {
        /// Optional exact link; `None` aggregates the declared network.
        link: Option<LinkId>,
    },
    /// Host-derived I/O completion count for one node.
    StorageCompletionCount {
        /// Declared world node or I/O sub-node.
        node: NodeId,
    },
    /// Host-derived scheduler event count.
    SchedulerEventCount,
}

/// Exact aggregation applied to one metric's canonical samples.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Aggregation {
    /// Count admitted samples using checked unsigned arithmetic.
    Count,
    /// Sum numeric samples using checked arithmetic.
    Sum,
    /// Select the minimum canonical value.
    Min,
    /// Select the maximum canonical value.
    Max,
    /// Compute an exact reduced rational mean.
    ExactMean,
    /// Count signed integer samples in declared ordered upper-bound bins.
    Histogram {
        /// Strictly increasing inclusive upper bounds.
        upper_bounds: Vec<i64>,
    },
    /// Retain the first sample in canonical event order.
    First,
    /// Retain the last sample in canonical event order.
    Last,
    /// Subtract the first numeric sample from the last with checked arithmetic.
    EventDelta,
}

/// One metric's immutable type, unit, source, and aggregation contract.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricDefinition {
    /// Stable identifier within the owning measurement.
    pub id: MetricId,
    /// Exact admitted sample and aggregate type.
    pub value_type: MetricValueType,
    /// Semantic unit fixed by scenario identity.
    pub unit: UnitId,
    /// Canonical sample source.
    pub source: MetricSource,
    /// Exact aggregation rule.
    pub aggregation: Aggregation,
}

/// One immutable scenario measurement-window contract.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementDefinition {
    /// Stable scenario-wide measurement identifier.
    pub id: MeasurementId,
    /// Boundary that opens the window.
    pub begin: BoundarySelector,
    /// Boundary that closes the window.
    pub end: BoundarySelector,
    /// Optional modeled timeout.
    pub timeout: Option<ModeledMeasurementTimeout>,
    /// Node cohort used by cohort-aware boundaries and samples.
    pub cohort: CohortPolicy,
    /// Nonempty canonical metric definitions.
    #[serde(rename = "metric")]
    pub metrics: Vec<MetricDefinition>,
}

/// Canonical validated measurement definitions owned by one scenario.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MeasurementDefinitions {
    definitions: Vec<MeasurementDefinition>,
    id: ContentHash,
    canonical: Vec<u8>,
}

impl Default for MeasurementDefinitions {
    fn default() -> Self {
        Self::empty()
    }
}

impl MeasurementDefinitions {
    /// Returns the empty measurement-definition component.
    #[must_use]
    pub fn empty() -> Self {
        let definitions = Vec::new();
        let canonical = b"[]";
        let id = ContentHash::from_canonical_hex_bytes(
            "crucible.model.measurement-definitions.v1",
            canonical,
        );
        Self {
            definitions,
            id,
            canonical: canonical.to_vec(),
        }
    }

    /// Validates, canonicalizes, and addresses scenario measurement definitions.
    ///
    /// # Errors
    ///
    /// Returns [`MeasurementDefinitionError`] for invalid identifiers, bounds,
    /// duplicate IDs, unknown world/plan/property references, illegal metric
    /// aggregation combinations, or unbounded modeled windows.
    pub fn new(
        world: &World,
        plan: &Plan,
        properties: &Properties,
        mut definitions: Vec<MeasurementDefinition>,
    ) -> Result<Self, MeasurementDefinitionError> {
        preflight_measurement_shape(&definitions)?;
        preflight_canonical_measurement_bytes(&definitions)?;
        canonicalize_and_validate_definitions(world, plan, properties, &mut definitions)?;
        Self::from_canonical_definitions(definitions)
    }

    /// Returns definitions in canonical measurement-ID order.
    #[must_use]
    pub fn definitions(&self) -> &[MeasurementDefinition] {
        &self.definitions
    }

    /// Returns whether this component declares no measurements.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.definitions.is_empty()
    }

    /// Returns the independently content-addressed component identity.
    #[must_use]
    pub const fn content_hash(&self) -> ContentHash {
        self.id
    }

    /// Returns deterministic JSON bytes used as the component's canonical body.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    pub(super) fn from_decoded_definitions(
        world: &World,
        plan: &Plan,
        properties: &Properties,
        definitions: Vec<MeasurementDefinition>,
    ) -> Result<Self, EngineError> {
        Self::new(world, plan, properties, definitions).map_err(|error| {
            scenario_serialization_error(format!("invalid measurement definitions: {error}"))
        })
    }

    fn from_canonical_definitions(
        definitions: Vec<MeasurementDefinition>,
    ) -> Result<Self, MeasurementDefinitionError> {
        let canonical = canonical_measurement_json(&definitions)?;
        let id = ContentHash::from_canonical_hex_bytes(
            "crucible.model.measurement-definitions.v1",
            &canonical,
        );
        Ok(Self {
            definitions,
            id,
            canonical,
        })
    }
}

fn preflight_measurement_shape(
    definitions: &[MeasurementDefinition],
) -> Result<(), MeasurementDefinitionError> {
    require_limit(
        "definitions",
        definitions.len(),
        MAX_MEASUREMENT_DEFINITIONS,
    )?;
    let mut total_metrics = 0_usize;
    for definition in definitions {
        let cohort_nodes = match &definition.cohort {
            CohortPolicy::All(nodes)
            | CohortPolicy::Any(nodes)
            | CohortPolicy::Quorum { nodes, .. } => nodes.len(),
        };
        require_limit("cohort nodes", cohort_nodes, MAX_MEASUREMENT_COHORT_NODES)?;
        preflight_boundary_shape(&definition.begin, 0)?;
        preflight_boundary_shape(&definition.end, 0)?;
        require_limit(
            "metrics per measurement",
            definition.metrics.len(),
            MAX_METRICS_PER_MEASUREMENT,
        )?;
        total_metrics = total_metrics.checked_add(definition.metrics.len()).ok_or(
            MeasurementDefinitionError::LimitExceeded {
                field: "scenario metrics",
                actual: usize::MAX,
                maximum: MAX_SCENARIO_METRICS,
            },
        )?;
        require_limit("scenario metrics", total_metrics, MAX_SCENARIO_METRICS)?;
        for metric in &definition.metrics {
            match &metric.value_type {
                MetricValueType::Enumerated { variants } => require_limit(
                    "metric enum variants",
                    variants.len(),
                    MAX_METRIC_ENUM_VARIANTS,
                )?,
                MetricValueType::IntegerVector {
                    maximum_elements, ..
                } => require_limit(
                    "metric vector elements",
                    *maximum_elements as usize,
                    MAX_METRIC_VECTOR_ELEMENTS as usize,
                )?,
                _ => {}
            }
            if let Aggregation::Histogram { upper_bounds } = &metric.aggregation {
                require_limit(
                    "histogram bounds",
                    upper_bounds.len(),
                    MAX_METRIC_HISTOGRAM_BOUNDS,
                )?;
            }
        }
    }
    Ok(())
}

fn preflight_boundary_shape(
    boundary: &BoundarySelector,
    depth: usize,
) -> Result<(), MeasurementDefinitionError> {
    if depth > MAX_MEASUREMENT_BOUNDARY_DEPTH {
        return Err(MeasurementDefinitionError::LimitExceeded {
            field: "boundary depth",
            actual: depth,
            maximum: MAX_MEASUREMENT_BOUNDARY_DEPTH,
        });
    }
    if let BoundarySelector::All { selectors } | BoundarySelector::Any { selectors } = boundary {
        require_limit(
            "compound boundary children",
            selectors.len(),
            MAX_MEASUREMENT_BOUNDARY_CHILDREN,
        )?;
        for selector in selectors {
            preflight_boundary_shape(selector, depth + 1)?;
        }
    }
    Ok(())
}

/// Stable failure while admitting measurement definitions.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MeasurementDefinitionError {
    /// An identifier violates the common bounded ASCII profile.
    #[error("invalid {kind} identifier `{value}`")]
    InvalidIdentifier {
        /// Identifier type or field.
        kind: &'static str,
        /// Rejected text.
        value: String,
    },
    /// A hard collection or depth bound was exceeded.
    #[error("measurement limit `{field}` exceeded: {actual} > {maximum}")]
    LimitExceeded {
        /// Bounded field.
        field: &'static str,
        /// Observed value.
        actual: usize,
        /// Maximum admitted value.
        maximum: usize,
    },
    /// A measurement or metric ID appeared more than once in its namespace.
    #[error("duplicate measurement identifier in `{namespace}`: `{id}`")]
    DuplicateId {
        /// Namespace containing the duplicate.
        namespace: &'static str,
        /// Duplicate identifier text.
        id: String,
    },
    /// A definition references an object absent from the scenario.
    #[error("measurement reference `{kind}` is not declared: `{id}`")]
    UnknownReference {
        /// Referenced namespace.
        kind: &'static str,
        /// Missing identifier.
        id: String,
    },
    /// A nonempty collection or nonzero modeled duration/count was required.
    #[error("measurement field `{field}` must be nonzero and nonempty")]
    EmptyValue {
        /// Invalid field.
        field: &'static str,
    },
    /// A quorum exceeds its cohort or is otherwise inconsistent.
    #[error("invalid measurement cohort quorum {required} for {members} members")]
    InvalidQuorum {
        /// Required members.
        required: u32,
        /// Available members.
        members: usize,
    },
    /// A metric aggregation is incompatible with its value type.
    #[error("metric `{metric}` uses an incompatible aggregation")]
    IncompatibleAggregation {
        /// Metric whose contract is invalid.
        metric: MetricId,
    },
    /// A model-owned source was paired with an incompatible sample type.
    #[error("metric `{metric}` uses an incompatible model-owned source type")]
    IncompatibleSource {
        /// Metric whose source/type contract is invalid.
        metric: MetricId,
    },
    /// A canonical representation could not be produced.
    #[error("measurement canonical encoding failed: {reason}")]
    CanonicalEncoding {
        /// Stable serialization detail.
        reason: String,
    },
}

fn canonicalize_and_validate_definitions(
    world: &World,
    plan: &Plan,
    properties: &Properties,
    definitions: &mut Vec<MeasurementDefinition>,
) -> Result<(), MeasurementDefinitionError> {
    require_limit(
        "definitions",
        definitions.len(),
        MAX_MEASUREMENT_DEFINITIONS,
    )?;
    definitions.sort_by(|left, right| left.id.cmp(&right.id));
    reject_duplicate_ids(
        "scenario measurements",
        definitions.iter().map(|definition| definition.id.as_str()),
    )?;

    let mut total_metrics = 0_usize;
    for definition in definitions {
        validate_measurement_identifier("measurement", definition.id.as_str())?;
        canonicalize_cohort(world, &mut definition.cohort)?;
        validate_boundary(world, plan, properties, &definition.begin, 0)?;
        validate_boundary(world, plan, properties, &definition.end, 0)?;
        if let Some(timeout) = &definition.timeout {
            validate_timeout(world, plan, timeout)?;
        }

        require_limit(
            "metrics per measurement",
            definition.metrics.len(),
            MAX_METRICS_PER_MEASUREMENT,
        )?;
        if definition.metrics.is_empty() {
            return Err(MeasurementDefinitionError::EmptyValue { field: "metrics" });
        }
        definition
            .metrics
            .sort_by(|left, right| left.id.cmp(&right.id));
        reject_duplicate_ids(
            "measurement metrics",
            definition.metrics.iter().map(|metric| metric.id.as_str()),
        )?;
        for metric in &mut definition.metrics {
            validate_metric(world, plan, metric)?;
        }
        total_metrics = total_metrics.checked_add(definition.metrics.len()).ok_or(
            MeasurementDefinitionError::LimitExceeded {
                field: "scenario metrics",
                actual: usize::MAX,
                maximum: MAX_SCENARIO_METRICS,
            },
        )?;
        require_limit("scenario metrics", total_metrics, MAX_SCENARIO_METRICS)?;
    }
    Ok(())
}

fn canonicalize_cohort(
    world: &World,
    cohort: &mut CohortPolicy,
) -> Result<(), MeasurementDefinitionError> {
    let (nodes, required) = match cohort {
        CohortPolicy::All(nodes) | CohortPolicy::Any(nodes) => (nodes, None),
        CohortPolicy::Quorum { nodes, required } => (nodes, Some(*required)),
    };
    require_limit("cohort nodes", nodes.len(), MAX_MEASUREMENT_COHORT_NODES)?;
    if nodes.is_empty() {
        return Err(MeasurementDefinitionError::EmptyValue {
            field: "cohort nodes",
        });
    }
    nodes.sort();
    if nodes.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(MeasurementDefinitionError::DuplicateId {
            namespace: "measurement cohort",
            id: nodes
                .windows(2)
                .find(|pair| pair[0] == pair[1])
                .map_or_else(String::new, |pair| pair[0].name.clone()),
        });
    }
    for node in nodes.iter() {
        require_world_vm_node(world, node)?;
    }
    if let Some(required) = required
        && (required == 0 || !usize::try_from(required).is_ok_and(|value| value <= nodes.len()))
    {
        return Err(MeasurementDefinitionError::InvalidQuorum {
            required,
            members: nodes.len(),
        });
    }
    Ok(())
}

fn validate_timeout(
    world: &World,
    plan: &Plan,
    timeout: &ModeledMeasurementTimeout,
) -> Result<(), MeasurementDefinitionError> {
    match timeout {
        ModeledMeasurementTimeout::VirtualTime { nanos } if *nanos == 0 => {
            Err(MeasurementDefinitionError::EmptyValue { field: "timeout" })
        }
        ModeledMeasurementTimeout::NodeIcount { node, instructions } => {
            require_world_vm_node(world, node)?;
            if *instructions == 0 {
                return Err(MeasurementDefinitionError::EmptyValue { field: "timeout" });
            }
            Ok(())
        }
        ModeledMeasurementTimeout::EventCount { event, count } => {
            require_plan_event(plan, event)?;
            if *count == 0 {
                return Err(MeasurementDefinitionError::EmptyValue { field: "timeout" });
            }
            Ok(())
        }
        ModeledMeasurementTimeout::VirtualTime { .. } => Ok(()),
    }
}

fn validate_boundary(
    world: &World,
    plan: &Plan,
    properties: &Properties,
    boundary: &BoundarySelector,
    depth: usize,
) -> Result<(), MeasurementDefinitionError> {
    if depth > MAX_MEASUREMENT_BOUNDARY_DEPTH {
        return Err(MeasurementDefinitionError::LimitExceeded {
            field: "boundary depth",
            actual: depth,
            maximum: MAX_MEASUREMENT_BOUNDARY_DEPTH,
        });
    }
    match boundary {
        BoundarySelector::ScenarioGenesis
        | BoundarySelector::ScenarioReady
        | BoundarySelector::VirtualTime { .. }
        | BoundarySelector::SchedulerQuiescence => Ok(()),
        BoundarySelector::PlanEvent { event } => require_plan_event(plan, event),
        BoundarySelector::FaultOpportunity { binding }
        | BoundarySelector::FaultTransition { binding }
        | BoundarySelector::FaultApplied { binding } => require_fault_binding(plan, binding),
        BoundarySelector::GuestMarker { marker, instance } => {
            validate_measurement_identifier("guest marker", &marker.name)?;
            if let Some(instance) = instance {
                validate_measurement_identifier("marker instance", instance.as_str())?;
            }
            if !world
                .vm_nodes()
                .iter()
                .any(|node| node.white_box.is_enabled())
            {
                return Err(MeasurementDefinitionError::UnknownReference {
                    kind: "white-box-enabled node for guest marker",
                    id: marker.name.clone(),
                });
            }
            Ok(())
        }
        BoundarySelector::PropertyVerdict { property } => {
            if properties
                .assertions()
                .iter()
                .any(|assertion| assertion.id == *property)
            {
                Ok(())
            } else {
                Err(MeasurementDefinitionError::UnknownReference {
                    kind: "property",
                    id: property.name.clone(),
                })
            }
        }
        BoundarySelector::NodeIcount { node, .. } => require_world_vm_node(world, node),
        BoundarySelector::EventCount { event, count } => {
            require_plan_event(plan, event)?;
            if *count == 0 {
                return Err(MeasurementDefinitionError::EmptyValue {
                    field: "boundary event count",
                });
            }
            Ok(())
        }
        BoundarySelector::NetworkIdle { link, window } => {
            if window.nanos == 0 {
                return Err(MeasurementDefinitionError::EmptyValue {
                    field: "network idle window",
                });
            }
            require_link(world, link.as_ref())
        }
        BoundarySelector::All { selectors } | BoundarySelector::Any { selectors } => {
            if selectors.is_empty() {
                return Err(MeasurementDefinitionError::EmptyValue {
                    field: "compound boundary",
                });
            }
            require_limit(
                "compound boundary children",
                selectors.len(),
                MAX_MEASUREMENT_BOUNDARY_CHILDREN,
            )?;
            for selector in selectors {
                validate_boundary(world, plan, properties, selector, depth + 1)?;
            }
            Ok(())
        }
    }
}

fn validate_metric(
    world: &World,
    plan: &Plan,
    metric: &mut MetricDefinition,
) -> Result<(), MeasurementDefinitionError> {
    validate_measurement_identifier("metric", metric.id.as_str())?;
    validate_measurement_identifier("unit", metric.unit.as_str())?;
    if SUPPORTED_METRIC_UNITS
        .binary_search(&metric.unit.as_str())
        .is_err()
    {
        return Err(MeasurementDefinitionError::UnknownReference {
            kind: "metric unit",
            id: metric.unit.as_str().to_owned(),
        });
    }
    match &mut metric.value_type {
        MetricValueType::Enumerated { variants } => {
            if variants.is_empty() {
                return Err(MeasurementDefinitionError::EmptyValue {
                    field: "metric enum variants",
                });
            }
            require_limit(
                "metric enum variants",
                variants.len(),
                MAX_METRIC_ENUM_VARIANTS,
            )?;
            variants.sort();
            for variant in variants.iter() {
                validate_measurement_identifier("metric enum variant", variant)?;
            }
            reject_duplicate_ids("metric enum variants", variants.iter().map(String::as_str))?;
        }
        MetricValueType::IntegerVector {
            maximum_elements, ..
        } if *maximum_elements == 0 || *maximum_elements > MAX_METRIC_VECTOR_ELEMENTS => {
            return Err(MeasurementDefinitionError::LimitExceeded {
                field: "metric vector elements",
                actual: *maximum_elements as usize,
                maximum: MAX_METRIC_VECTOR_ELEMENTS as usize,
            });
        }
        _ => {}
    }
    match &metric.source {
        MetricSource::Guest => {
            if !world
                .vm_nodes()
                .iter()
                .any(|node| node.white_box.is_enabled())
            {
                return Err(MeasurementDefinitionError::UnknownReference {
                    kind: "white-box-enabled node for guest metric",
                    id: metric.id.as_str().to_owned(),
                });
            }
        }
        MetricSource::NodeIcount { node } => require_world_vm_node(world, node)?,
        MetricSource::StorageCompletionCount { node } => require_world_node(world, node)?,
        MetricSource::ModeledEventCount { event } => require_plan_event(plan, event)?,
        MetricSource::NetworkModeledDropCount { link } => require_link(world, link.as_ref())?,
        MetricSource::VirtualTime | MetricSource::SchedulerEventCount => {}
    }
    if !matches!(metric.source, MetricSource::Guest)
        && !matches!(metric.value_type, MetricValueType::UnsignedInteger)
    {
        return Err(MeasurementDefinitionError::IncompatibleSource {
            metric: metric.id.clone(),
        });
    }
    let expected_unit = match &metric.source {
        MetricSource::Guest => None,
        MetricSource::VirtualTime => Some("virtual_nanoseconds"),
        MetricSource::NodeIcount { .. } => Some("instructions"),
        MetricSource::ModeledEventCount { .. } | MetricSource::SchedulerEventCount => {
            Some("events")
        }
        MetricSource::NetworkModeledDropCount { .. } => Some("packets"),
        MetricSource::StorageCompletionCount { .. } => Some("operations"),
    };
    if expected_unit.is_some_and(|unit| metric.unit.as_str() != unit) {
        return Err(MeasurementDefinitionError::IncompatibleSource {
            metric: metric.id.clone(),
        });
    }
    if let Aggregation::Histogram { upper_bounds } = &mut metric.aggregation {
        if upper_bounds.is_empty() {
            return Err(MeasurementDefinitionError::EmptyValue {
                field: "histogram bounds",
            });
        }
        require_limit(
            "histogram bounds",
            upper_bounds.len(),
            MAX_METRIC_HISTOGRAM_BOUNDS,
        )?;
        upper_bounds.sort();
        if upper_bounds.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(MeasurementDefinitionError::DuplicateId {
                namespace: "histogram bounds",
                id: upper_bounds
                    .windows(2)
                    .find(|pair| pair[0] == pair[1])
                    .map_or_else(String::new, |pair| pair[0].to_string()),
            });
        }
        if matches!(metric.value_type, MetricValueType::UnsignedInteger)
            && upper_bounds.iter().any(|bound| *bound < 0)
        {
            return Err(MeasurementDefinitionError::IncompatibleAggregation {
                metric: metric.id.clone(),
            });
        }
    }
    let numeric = matches!(
        metric.value_type,
        MetricValueType::SignedInteger
            | MetricValueType::UnsignedInteger
            | MetricValueType::ReducedRational
    );
    let ordered = numeric || matches!(metric.value_type, MetricValueType::Boolean);
    let compatible = match metric.aggregation {
        Aggregation::Count | Aggregation::First | Aggregation::Last => true,
        Aggregation::Sum | Aggregation::ExactMean | Aggregation::EventDelta => numeric,
        Aggregation::Min | Aggregation::Max => ordered,
        Aggregation::Histogram { .. } => matches!(
            metric.value_type,
            MetricValueType::SignedInteger | MetricValueType::UnsignedInteger
        ),
    };
    if !compatible {
        return Err(MeasurementDefinitionError::IncompatibleAggregation {
            metric: metric.id.clone(),
        });
    }
    Ok(())
}

fn require_world_node(world: &World, node: &NodeId) -> Result<(), MeasurementDefinitionError> {
    if world.nodes().iter().any(|candidate| candidate.id() == node) {
        Ok(())
    } else {
        Err(MeasurementDefinitionError::UnknownReference {
            kind: "world node",
            id: node.name.clone(),
        })
    }
}

fn require_world_vm_node(world: &World, node: &NodeId) -> Result<(), MeasurementDefinitionError> {
    if world
        .vm_nodes()
        .iter()
        .any(|candidate| candidate.id == *node)
    {
        Ok(())
    } else {
        Err(MeasurementDefinitionError::UnknownReference {
            kind: "world VM node",
            id: node.name.clone(),
        })
    }
}

fn require_plan_event(plan: &Plan, event: &EventId) -> Result<(), MeasurementDefinitionError> {
    if plan
        .event_graph()
        .events()
        .iter()
        .any(|candidate| candidate.id == *event)
    {
        Ok(())
    } else {
        Err(MeasurementDefinitionError::UnknownReference {
            kind: "plan event",
            id: event.name.clone(),
        })
    }
}

fn require_fault_binding(
    plan: &Plan,
    binding: &FaultObjectId,
) -> Result<(), MeasurementDefinitionError> {
    if plan
        .fault_signals()
        .bindings()
        .iter()
        .any(|candidate| candidate.id() == binding)
    {
        Ok(())
    } else {
        Err(MeasurementDefinitionError::UnknownReference {
            kind: "fault binding",
            id: binding.as_str().to_owned(),
        })
    }
}

fn require_link(world: &World, link: Option<&LinkId>) -> Result<(), MeasurementDefinitionError> {
    match link {
        None if world.links().is_empty() => Err(MeasurementDefinitionError::UnknownReference {
            kind: "world network",
            id: String::from("<empty>"),
        }),
        None => Ok(()),
        Some(link)
            if world.links().iter().any(|candidate| {
                let (left, right) = candidate.endpoints();
                LinkId::for_endpoints(left, right) == *link
            }) =>
        {
            Ok(())
        }
        Some(link) => Err(MeasurementDefinitionError::UnknownReference {
            kind: "world link",
            id: link.name.clone(),
        }),
    }
}

fn canonical_measurement_json(
    definitions: &[MeasurementDefinition],
) -> Result<Vec<u8>, MeasurementDefinitionError> {
    serde_json::to_vec(definitions).map_err(|error| MeasurementDefinitionError::CanonicalEncoding {
        reason: error.to_string(),
    })
}

fn preflight_canonical_measurement_bytes(
    definitions: &[MeasurementDefinition],
) -> Result<(), MeasurementDefinitionError> {
    let mut counter = BoundedByteCounter {
        length: 0,
        maximum: MAX_MEASUREMENT_DEFINITION_BYTES,
        exceeded: false,
    };
    let encoded = serde_json::to_writer(&mut counter, definitions);
    if counter.exceeded {
        return Err(MeasurementDefinitionError::LimitExceeded {
            field: "canonical measurement bytes",
            actual: counter.length,
            maximum: MAX_MEASUREMENT_DEFINITION_BYTES,
        });
    }
    encoded.map_err(|error| MeasurementDefinitionError::CanonicalEncoding {
        reason: error.to_string(),
    })
}

struct BoundedByteCounter {
    length: usize,
    maximum: usize,
    exceeded: bool,
}

impl io::Write for BoundedByteCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.length = match self.length.checked_add(bytes.len()) {
            Some(length) => length,
            None => {
                self.exceeded = true;
                self.length = usize::MAX;
                return Err(io::Error::other(
                    "canonical measurement definition byte count overflowed",
                ));
            }
        };
        if self.length > self.maximum {
            self.exceeded = true;
            return Err(io::Error::other(
                "canonical measurement definition byte limit exceeded",
            ));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn validate_measurement_identifier(
    kind: &'static str,
    value: &str,
) -> Result<(), MeasurementDefinitionError> {
    if value.is_empty()
        || value.len() > MAX_MEASUREMENT_IDENTIFIER_BYTES
        || !value.is_ascii()
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':')
        })
    {
        return Err(MeasurementDefinitionError::InvalidIdentifier {
            kind,
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn reject_duplicate_ids<'a>(
    namespace: &'static str,
    values: impl Iterator<Item = &'a str>,
) -> Result<(), MeasurementDefinitionError> {
    let mut previous: Option<&str> = None;
    for value in values {
        if previous == Some(value) {
            return Err(MeasurementDefinitionError::DuplicateId {
                namespace,
                id: value.to_owned(),
            });
        }
        previous = Some(value);
    }
    Ok(())
}

fn require_limit(
    field: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), MeasurementDefinitionError> {
    if actual > maximum {
        Err(MeasurementDefinitionError::LimitExceeded {
            field,
            actual,
            maximum,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
