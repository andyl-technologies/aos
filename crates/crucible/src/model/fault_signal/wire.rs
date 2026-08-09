//! Versioned persistence DTOs for signal programs and fault bindings.
//!
//! The wire form contains authored contracts rather than cached identities or
//! mutable runtime state. Decoding always re-enters the public admission
//! constructors, so serialized input cannot choose identities or bypass graph,
//! mapping, selector, effect, or resource validation.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod toml_integer_tests {
    use super::*;

    #[test]
    fn wide_u64_escape_has_one_canonical_threshold() {
        assert_eq!(
            toml_to_json(toml::Value::Integer(i64::MAX))
                .unwrap_or_else(|error| panic!("decode i64::MAX: {error}")),
            serde_json::json!(i64::MAX),
        );
        assert!(matches!(
            toml_to_json(toml::Value::String(String::from("u64:9223372036854775807"))),
            Err(FaultSignalTomlWireError::NonCanonicalU64String(value))
                if value == i64::MAX as u64
        ));
        assert_eq!(
            toml_to_json(toml::Value::String(String::from("u64:9223372036854775808")))
                .unwrap_or_else(|error| panic!("decode i64::MAX + 1: {error}")),
            serde_json::json!(9_223_372_036_854_775_808_u64),
        );
    }

    #[test]
    fn wide_u64_escape_rejects_small_malformed_and_wrongly_typed_values() {
        assert!(matches!(
            toml_to_json(toml::Value::String(String::from("u64:5"))),
            Err(FaultSignalTomlWireError::NonCanonicalU64String(5))
        ));
        assert!(matches!(
            toml_to_json(toml::Value::String(String::from("u64:not-a-number"))),
            Err(FaultSignalTomlWireError::InvalidU64String(_))
        ));
        assert!(matches!(
            toml_to_json(toml::Value::String(String::from(
                "u64:09223372036854775808"
            ))),
            Err(FaultSignalTomlWireError::InvalidU64String(_))
        ));
        assert!(matches!(
            toml_to_json(toml::Value::String(String::from(
                "u64:+9223372036854775808"
            ))),
            Err(FaultSignalTomlWireError::InvalidU64String(_))
        ));

        let i64_value = toml::Value::Table(toml::toml! {
            type = "i64"
            value = "u64:9223372036854775808"
        });
        assert!(from_toml_value::<SignalValue>(i64_value).is_err());

        let u32_value = toml::Value::Table(toml::toml! {
            type = "probability_millionths"
            value = "u64:9223372036854775808"
        });
        assert!(from_toml_value::<SignalValue>(u32_value).is_err());
    }
}

impl SignalProgramWire {
    fn from_program(program: &SignalProgram) -> Self {
        Self {
            node: program.nodes().to_vec(),
            exported_output: program.exported_outputs().to_vec(),
        }
    }

    fn admit(self, limits: SignalResourceLimits) -> Result<SignalProgram, FaultSignalWireError> {
        SignalProgram::new(self.node, self.exported_output, limits)
            .map_err(FaultSignalWireError::Program)
    }
}

impl FaultBindingWire {
    pub(super) fn from_binding(binding: &FaultBinding) -> Self {
        Self {
            id: binding.id().clone(),
            program: binding.program(),
            signals: binding.signals().to_vec(),
            sampling: binding.sampling().clone(),
            mapping: binding.mapping().clone(),
            selector: binding.selector().clone(),
            phases: binding.phases().clone(),
            effect: EffectRequestWire {
                semantic_version: EFFECT_SEMANTIC_VERSION,
                lifetime: binding.effect().lifetime(),
                specification: binding.effect().specification().clone(),
            },
            opportunity_filter: binding.opportunity_filter().cloned(),
            search: binding.search().clone(),
            observability: binding.observability(),
            transition_declaration: binding
                .transition_declaration()
                .map(StateTransitionTableWire::from_declaration),
            service_declaration: binding.service_declaration().cloned(),
        }
    }

    pub(super) fn admit(
        self,
        program: &SignalProgram,
    ) -> Result<FaultBinding, FaultSignalWireError> {
        validate_mapping_declarations(
            &self.mapping,
            self.transition_declaration.as_ref(),
            self.service_declaration.as_ref(),
        )?;
        let selector = revalidate_selector(self.selector)?;
        let effect = EffectRequest::new(
            self.effect.semantic_version,
            self.effect.lifetime,
            self.effect.specification,
        )
        .map_err(FaultSignalWireError::Effect)?;
        let registry = BindingMappingRegistry::new(
            self.transition_declaration
                .map(StateTransitionTableWire::admit)
                .transpose()?
                .into_iter()
                .collect(),
            self.service_declaration.into_iter().collect(),
        )
        .map_err(FaultSignalWireError::Binding)?;
        FaultBinding::new_with_registry(
            self.id,
            self.signals,
            self.sampling,
            self.mapping,
            selector,
            self.phases,
            effect,
            self.opportunity_filter,
            self.search,
            self.observability,
            program,
            &registry,
        )
        .map_err(FaultSignalWireError::Binding)
    }
}

fn validate_mapping_declarations(
    mapping: &BindingMapping,
    transition: Option<&StateTransitionTableWire>,
    service: Option<&ServiceProfileDeclaration>,
) -> Result<(), FaultSignalWireError> {
    let (expected_transition, expected_service) = match mapping {
        BindingMapping::StateTransition { transition_table } => (Some(transition_table), None),
        BindingMapping::ServiceProfile { service_profile } => (None, Some(service_profile)),
        _ => (None, None),
    };
    match (expected_transition, transition) {
        (Some(expected), Some(actual)) if expected == &actual.id => {}
        (Some(expected), Some(actual)) => {
            return Err(FaultSignalWireError::MappingDeclarationMismatch {
                expected: expected.clone(),
                actual: actual.id.clone(),
            });
        }
        (Some(expected), None) => {
            return Err(FaultSignalWireError::MissingMappingDeclaration {
                declaration: expected.clone(),
            });
        }
        (None, Some(actual)) => {
            return Err(FaultSignalWireError::UnexpectedMappingDeclaration {
                declaration: actual.id.clone(),
            });
        }
        (None, None) => {}
    }
    match (expected_service, service) {
        (Some(expected), Some(actual)) if expected == &actual.id => Ok(()),
        (Some(expected), Some(actual)) => Err(FaultSignalWireError::MappingDeclarationMismatch {
            expected: expected.clone(),
            actual: actual.id.clone(),
        }),
        (Some(expected), None) => Err(FaultSignalWireError::MissingMappingDeclaration {
            declaration: expected.clone(),
        }),
        (None, Some(actual)) => Err(FaultSignalWireError::UnexpectedMappingDeclaration {
            declaration: actual.id.clone(),
        }),
        (None, None) => Ok(()),
    }
}

impl StateTransitionTableWire {
    fn from_declaration(declaration: &StateTransitionTableDeclaration) -> Self {
        Self {
            id: declaration.id.clone(),
            semantic_version: declaration.semantic_version,
            input: declaration.input.clone(),
            effect: declaration.effect,
            transition: declaration
                .transitions
                .iter()
                .map(|(request, transition)| StateTransitionWireEntry {
                    request: request.clone(),
                    transition: transition.clone(),
                })
                .collect(),
            default_transition: declaration.default_transition.clone(),
        }
    }

    fn admit(self) -> Result<StateTransitionTableDeclaration, FaultSignalWireError> {
        let mut transitions = BTreeMap::new();
        for entry in self.transition {
            if transitions
                .insert(entry.request, entry.transition)
                .is_some()
            {
                return Err(FaultSignalWireError::DuplicateTransitionRequest {
                    declaration: self.id,
                });
            }
        }
        Ok(StateTransitionTableDeclaration {
            id: self.id,
            semantic_version: self.semantic_version,
            input: self.input,
            effect: self.effect,
            transitions,
            default_transition: self.default_transition,
        })
    }
}

fn revalidate_selector(selector: TargetSelector) -> Result<TargetSelector, FaultSignalWireError> {
    fn targets(value: ResolvedTargetSet) -> Result<ResolvedTargetSet, FaultSignalWireError> {
        ResolvedTargetSet::new(value.targets().to_vec(), value.allow_empty())
            .map_err(FaultSignalWireError::Binding)
    }

    Ok(match selector {
        TargetSelector::Exact(value) => TargetSelector::Exact(targets(value)?),
        TargetSelector::TargetSet(value) => TargetSelector::TargetSet(targets(value)?),
        TargetSelector::FaultDomain { domain, resolved } => TargetSelector::FaultDomain {
            domain,
            resolved: targets(resolved)?,
        },
        TargetSelector::DynamicPath {
            path,
            initial,
            membership_semantic_version,
        } => TargetSelector::DynamicPath {
            path,
            initial: targets(initial)?,
            membership_semantic_version,
        },
    })
}

/// Failure to decode and re-admit a persisted fault-signal contract.
#[derive(Debug)]
pub(crate) enum FaultSignalWireError {
    /// The persisted contract selected an unsupported semantic version.
    Version {
        /// Exact implemented version.
        expected: u16,
        /// Persisted version.
        actual: u16,
    },
    /// The plan-owned resource contract failed validation.
    ResourceLimit(FaultResourceLimitError),
    /// A signal graph failed admission.
    Program(SignalProgramError),
    /// A binding names a signal program absent from the same wire layer.
    MissingProgram {
        /// Authored binding identity.
        binding: FaultObjectId,
        /// Missing program identity.
        program: ContentHash,
    },
    /// A transition table repeated one exact request value.
    DuplicateTransitionRequest {
        /// Authored transition-table identity.
        declaration: FaultObjectId,
    },
    /// A named mapping omitted its exact referenced declaration.
    MissingMappingDeclaration {
        /// Referenced declaration identity.
        declaration: FaultObjectId,
    },
    /// A mapping carried a declaration of an inapplicable kind.
    UnexpectedMappingDeclaration {
        /// Unexpected declaration identity.
        declaration: FaultObjectId,
    },
    /// A named mapping and supplied declaration used different identities.
    MappingDeclarationMismatch {
        /// Identity referenced by the mapping.
        expected: FaultObjectId,
        /// Identity supplied by the wire declaration.
        actual: FaultObjectId,
    },
    /// Typed effect validation failed.
    Effect(FaultContractError),
    /// Binding or mapping-registry validation failed.
    Binding(BindingError),
    /// Complete plan validation failed.
    Plan(FaultSignalPlanError),
}

impl fmt::Display for FaultSignalWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Version { expected, actual } => write!(
                formatter,
                "fault signal wire version mismatch: expected {expected}, found {actual}"
            ),
            Self::MissingProgram { binding, program } => write!(
                formatter,
                "fault binding `{}` references missing signal program {}",
                binding.as_str(),
                program.to_hex()
            ),
            Self::DuplicateTransitionRequest { declaration } => write!(
                formatter,
                "state-transition declaration `{}` repeats a request value",
                declaration.as_str()
            ),
            Self::MissingMappingDeclaration { declaration } => write!(
                formatter,
                "mapping omits referenced declaration `{}`",
                declaration.as_str()
            ),
            Self::UnexpectedMappingDeclaration { declaration } => write!(
                formatter,
                "mapping carries unexpected declaration `{}`",
                declaration.as_str()
            ),
            Self::MappingDeclarationMismatch { expected, actual } => write!(
                formatter,
                "mapping references declaration `{}` but carries `{}`",
                expected.as_str(),
                actual.as_str()
            ),
            Self::Program(error) => write!(formatter, "signal program admission failed: {error}"),
            Self::ResourceLimit(error) => {
                write!(formatter, "fault resource limit admission failed: {error}")
            }
            Self::Effect(error) => write!(formatter, "effect admission failed: {error}"),
            Self::Binding(error) => write!(formatter, "fault binding admission failed: {error}"),
            Self::Plan(error) => write!(formatter, "fault signal plan admission failed: {error}"),
        }
    }
}

impl Error for FaultSignalWireError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ResourceLimit(error) => Some(error),
            Self::Program(error) => Some(error),
            Self::Effect(error) => Some(error),
            Self::Binding(error) => Some(error),
            Self::Plan(error) => Some(error),
            Self::Version { .. }
            | Self::MissingProgram { .. }
            | Self::DuplicateTransitionRequest { .. }
            | Self::MissingMappingDeclaration { .. }
            | Self::UnexpectedMappingDeclaration { .. }
            | Self::MappingDeclarationMismatch { .. } => None,
        }
    }
}
