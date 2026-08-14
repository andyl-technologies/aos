//! Strict TOML projection for signal-driven fault plans.

use super::*;

/// Exact semantic version of the persisted fault-signal plan contract.
pub(crate) const FAULT_SIGNAL_PLAN_WIRE_VERSION: u16 = 2;

/// Authored wire form for one complete fault-signal layer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FaultSignalPlanWire {
    /// Exact wire semantic version.
    pub(crate) semantic_version: u16,
    /// Complete scenario-owned resource contract.
    pub(crate) resource_limits: FaultResourceLimits,
    /// Authored signal programs.
    pub(crate) signal_program: Vec<SignalProgramWire>,
    /// Authored signal-to-effect bindings.
    pub(crate) fault_binding: Vec<FaultBindingWire>,
}

/// Authored wire form for one validated signal graph.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignalProgramWire {
    /// Signal nodes in arbitrary presentation order.
    pub(crate) node: Vec<SignalNode>,
    /// Explicit exported node identities.
    pub(crate) exported_output: Vec<SignalId>,
}

/// Authored wire form for one validated effect request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EffectRequestWire {
    /// Exact effect-registry semantic version.
    pub(crate) semantic_version: u16,
    /// Requested contribution lifetime.
    pub(crate) lifetime: EffectLifetime,
    /// Closed adapter-owned effect parameters.
    pub(crate) specification: EffectSpecification,
}

/// Authored wire form for one signal-to-effect binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FaultBindingWire {
    /// Stable authored binding identity.
    pub(crate) id: FaultObjectId,
    /// Exact content identity of the referenced signal program.
    pub(crate) program: ContentHash,
    /// Exported signal inputs.
    pub(crate) signals: Vec<SignalId>,
    /// Sampling coordinate contract.
    pub(crate) sampling: BindingSampling,
    /// Closed signal-to-effect mapping.
    pub(crate) mapping: BindingMapping,
    /// Already-resolved target selector and provenance.
    pub(crate) selector: TargetSelector,
    /// Nonempty adapter phase set.
    pub(crate) phases: BTreeSet<FaultPhase>,
    /// Validated effect template fields.
    pub(crate) effect: EffectRequestWire,
    /// Optional opportunity predicate.
    pub(crate) opportunity_filter: Option<OpportunityFilter>,
    /// Bounded explorer policy.
    pub(crate) search: BindingSearchPolicy,
    /// Sample and application retention policy.
    pub(crate) observability: BindingObservabilityPolicy,
    /// Referenced state-transition declaration, when used.
    pub(crate) transition_declaration: Option<StateTransitionTableWire>,
    /// Referenced service-profile declaration, when used.
    pub(crate) service_declaration: Option<ServiceProfileDeclaration>,
}

/// JSON/TOML-safe wire form of an exhaustive state-transition declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StateTransitionTableWire {
    /// Stable declaration identity.
    pub(crate) id: FaultObjectId,
    /// Exact declaration semantic version.
    pub(crate) semantic_version: u16,
    /// Closed request value type.
    pub(crate) input: SignalValueType,
    /// Exact effect family selected by transition results.
    pub(crate) effect: EffectKind,
    /// Canonically ordered request-to-transition entries.
    pub(crate) transition: Vec<StateTransitionWireEntry>,
    /// Exhaustive fallback for unknown request values.
    pub(crate) default_transition: FaultObjectId,
}

/// One state-transition request and its typed adapter transition identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StateTransitionWireEntry {
    /// Exact request value.
    pub(crate) request: SignalValue,
    /// Selected transition identity.
    pub(crate) transition: FaultObjectId,
}

impl FaultSignalPlanWire {
    /// Captures authored contracts without derived identities.
    pub(crate) fn from_plan(plan: &FaultSignalPlan) -> Self {
        Self {
            semantic_version: FAULT_SIGNAL_PLAN_WIRE_VERSION,
            resource_limits: plan.resource_limits(),
            signal_program: plan
                .programs()
                .iter()
                .map(SignalProgramWire::from_program)
                .collect(),
            fault_binding: plan
                .bindings()
                .iter()
                .map(FaultBindingWire::from_binding)
                .collect(),
        }
    }

    /// Re-enters every admission constructor and derives canonical identities.
    ///
    /// # Errors
    ///
    /// Returns [`FaultSignalWireError`] for a semantic-version mismatch, an
    /// invalid signal program, a missing referenced program, an invalid effect,
    /// mapping registry, selector, or binding, or final plan admission failure.
    pub(crate) fn admit(self) -> Result<FaultSignalPlan, FaultSignalWireError> {
        if self.semantic_version != FAULT_SIGNAL_PLAN_WIRE_VERSION {
            return Err(FaultSignalWireError::Version {
                expected: FAULT_SIGNAL_PLAN_WIRE_VERSION,
                actual: self.semantic_version,
            });
        }
        let signal_limits = self
            .resource_limits
            .signal_limits()
            .map_err(FaultSignalWireError::ResourceLimit)?;
        let programs = self
            .signal_program
            .into_iter()
            .map(|program| program.admit(signal_limits))
            .collect::<Result<Vec<_>, _>>()?;
        let by_id = programs
            .iter()
            .map(|program| (program.id(), program))
            .collect::<BTreeMap<_, _>>();
        let bindings = self
            .fault_binding
            .into_iter()
            .map(|binding| {
                let program = by_id.get(&binding.program).copied().ok_or_else(|| {
                    FaultSignalWireError::MissingProgram {
                        binding: binding.id.clone(),
                        program: binding.program,
                    }
                })?;
                binding.admit(program)
            })
            .collect::<Result<Vec<_>, _>>()?;
        FaultSignalPlan::new(programs, bindings, self.resource_limits)
            .map_err(FaultSignalWireError::Plan)
    }
}

const TOML_U64_PREFIX: &str = "u64:";

pub(super) fn to_toml_value<T: Serialize>(
    value: &T,
) -> Result<toml::Value, FaultSignalTomlWireError> {
    json_to_toml(serde_json::to_value(value).map_err(FaultSignalTomlWireError::Json)?)?
        .ok_or(FaultSignalTomlWireError::TopLevelNull)
}

fn json_to_toml(value: serde_json::Value) -> Result<Option<toml::Value>, FaultSignalTomlWireError> {
    Ok(match value {
        serde_json::Value::Null => None,
        serde_json::Value::Bool(value) => Some(toml::Value::Boolean(value)),
        serde_json::Value::String(value) => Some(toml::Value::String(value)),
        serde_json::Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                Some(toml::Value::Integer(value))
            } else if let Some(value) = value.as_u64() {
                Some(toml::Value::String(format!("{TOML_U64_PREFIX}{value}")))
            } else {
                return Err(FaultSignalTomlWireError::NonIntegerNumber);
            }
        }
        serde_json::Value::Array(values) => Some(toml::Value::Array(
            values
                .into_iter()
                .map(|value| json_to_toml(value)?.ok_or(FaultSignalTomlWireError::ArrayNull))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        serde_json::Value::Object(values) => {
            let mut table = toml::map::Map::new();
            for (key, value) in values {
                if let Some(value) = json_to_toml(value)? {
                    table.insert(key, value);
                }
            }
            Some(toml::Value::Table(table))
        }
    })
}

pub(super) fn from_toml_value<T: for<'de> Deserialize<'de>>(
    value: toml::Value,
) -> Result<T, FaultSignalTomlWireError> {
    serde_json::from_value(toml_to_json(value)?).map_err(FaultSignalTomlWireError::Json)
}

fn toml_to_json(value: toml::Value) -> Result<serde_json::Value, FaultSignalTomlWireError> {
    Ok(match value {
        toml::Value::String(value) => {
            if let Some(encoded) = value.strip_prefix(TOML_U64_PREFIX) {
                let value = encoded
                    .parse::<u64>()
                    .map_err(|_| FaultSignalTomlWireError::InvalidU64String(value.clone()))?;
                if encoded != value.to_string() {
                    return Err(FaultSignalTomlWireError::InvalidU64String(format!(
                        "{TOML_U64_PREFIX}{encoded}"
                    )));
                }
                if value <= i64::MAX as u64 {
                    return Err(FaultSignalTomlWireError::NonCanonicalU64String(value));
                }
                serde_json::Value::Number(value.into())
            } else {
                serde_json::Value::String(value)
            }
        }
        toml::Value::Integer(value) => serde_json::Value::Number(value.into()),
        toml::Value::Boolean(value) => serde_json::Value::Bool(value),
        toml::Value::Array(values) => serde_json::Value::Array(
            values
                .into_iter()
                .map(toml_to_json)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        toml::Value::Table(values) => serde_json::Value::Object(
            values
                .into_iter()
                .map(|(key, value)| Ok((key, toml_to_json(value)?)))
                .collect::<Result<serde_json::Map<_, _>, FaultSignalTomlWireError>>()?,
        ),
        toml::Value::Float(_) => return Err(FaultSignalTomlWireError::Float),
        toml::Value::Datetime(_) => return Err(FaultSignalTomlWireError::Datetime),
    })
}

/// Failure to translate the typed wire contract through TOML's signed integers.
#[derive(Debug)]
pub(crate) enum FaultSignalTomlWireError {
    /// Typed JSON conversion failed.
    Json(serde_json::Error),
    /// A noninteger JSON number entered the integer-only contract.
    NonIntegerNumber,
    /// A top-level row serialized as null.
    TopLevelNull,
    /// An array contained a null value, which TOML cannot represent.
    ArrayNull,
    /// A reserved wide-integer string was malformed.
    InvalidU64String(String),
    /// A reserved wide-integer string encoded a value representable by TOML.
    NonCanonicalU64String(u64),
    /// Floating-point TOML is outside the exact signal contract.
    Float,
    /// TOML datetimes are outside the exact signal contract.
    Datetime,
}

impl fmt::Display for FaultSignalTomlWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "fault signal TOML conversion: {error}"),
            Self::NonIntegerNumber => formatter.write_str("fault signal TOML contains a float"),
            Self::TopLevelNull => formatter.write_str("fault signal TOML row is null"),
            Self::ArrayNull => formatter.write_str("fault signal TOML array contains null"),
            Self::InvalidU64String(value) => {
                write!(formatter, "invalid fault signal wide integer `{value}`")
            }
            Self::NonCanonicalU64String(value) => write!(
                formatter,
                "fault signal wide integer `u64:{value}` must be written as a TOML integer"
            ),
            Self::Float => formatter.write_str("floating-point fault signal TOML is forbidden"),
            Self::Datetime => formatter.write_str("datetime fault signal TOML is forbidden"),
        }
    }
}

impl Error for FaultSignalTomlWireError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}
