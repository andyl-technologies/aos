//! Typed signal-to-effect mappings and named mapping declarations.

use super::*;
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
    pub(super) fn accepts(self, shape: &SignalShape) -> bool {
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

    pub(super) fn belongs_to(self, effect: EffectKind) -> bool {
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

    pub(in crate::model::fault_signal) fn accepts_value(self, value: &SignalValue) -> bool {
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
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
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
    #[serde(
        serialize_with = "serialize_transition_map",
        deserialize_with = "deserialize_transition_map"
    )]
    pub transitions: BTreeMap<SignalValue, FaultObjectId>,
    /// Mandatory transition for every request not present in `transitions`.
    pub default_transition: FaultObjectId,
}

fn deserialize_transition_map<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<SignalValue, FaultObjectId>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let entries =
        <Vec<(SignalValue, FaultObjectId)> as serde::Deserialize>::deserialize(deserializer)?;
    let mut transitions = BTreeMap::new();
    for (input, output) in entries {
        if transitions.insert(input, output).is_some() {
            return Err(serde::de::Error::custom("duplicate state transition input"));
        }
    }
    Ok(transitions)
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
    pub(super) transition_tables: BTreeMap<FaultObjectId, StateTransitionTableDeclaration>,
    pub(super) service_profiles: BTreeMap<FaultObjectId, ServiceProfileDeclaration>,
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

    pub(super) fn validate_mapping(
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
