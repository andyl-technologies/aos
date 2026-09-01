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

pub(super) mod toml_codec;

pub(crate) use toml_codec::*;

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
