//! Selected-provider evaluation and fragment authority checks.

use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::document::Contribution;
use aos_ability_model::identity::compare_request_ids;
use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityActivationMode, AbilityValue, AggregateOutput, ArtifactReference,
    Binding, BindingRequest, ControllerAssignment, DesiredStateDocument, ImplementationKind,
    InstanceId, InterfaceKey, LocalKey, PackageDocument, ProviderImplementation,
    ProviderImplementationReference, ResourceRevision, ValuePhase, compare_resource_ids,
};
use aos_ability_validate::ValidationContext;
use aos_contract::Sha256Digest;
use serde::Serialize;

use crate::resolution::{EnabledProviderSelection, ResolutionPolicyDocument};

use super::{
    CompositionError, CompositionEvaluation, CompositionEvaluationResult, CompositionEvaluator,
    CompositionFragment, CompositionLimits, EvaluationError, bounded_constraint, child_request_id,
    validate_child_depth,
};

pub(super) struct PureProviderEvaluationInputs<'a> {
    pub(super) context: &'a ValidationContext,
    pub(super) desired_state: &'a DesiredStateDocument,
    pub(super) bindings: &'a [Binding],
    pub(super) enabled_providers: &'a [EnabledProviderSelection],
    pub(super) packages: &'a [PackageDocument],
    pub(super) package_index: &'a BTreeMap<Sha256Digest, usize>,
}

pub(super) struct EvaluationRecorder<'a, E> {
    pub(super) evaluator: &'a mut E,
    pub(super) evaluations: &'a mut u32,
    pub(super) bytes: &'a mut u64,
    pub(super) trace: &'a mut Vec<CompositionEvaluation>,
}

pub(super) fn evaluate_pure_providers<E: CompositionEvaluator>(
    inputs: PureProviderEvaluationInputs<'_>,
    recorder: EvaluationRecorder<'_, E>,
    limits: CompositionLimits,
) -> Result<Vec<(InstanceId, CompositionFragment)>, CompositionError> {
    let PureProviderEvaluationInputs {
        context,
        desired_state,
        bindings,
        enabled_providers,
        packages,
        package_index,
    } = inputs;
    let EvaluationRecorder {
        evaluator,
        evaluations,
        bytes: evaluation_bytes,
        trace: evaluation_trace,
    } = recorder;
    let requests: BTreeMap<_, _> = desired_state
        .child_requests
        .iter()
        .map(|request| (request.id.clone(), request))
        .collect();
    let mut groups: BTreeMap<(InstanceId, Sha256Digest), ProviderEvaluationGroup<'_>> =
        BTreeMap::new();
    for binding in bindings {
        let group = groups
            .entry((binding.provider.clone(), binding.implementation.descriptor))
            .or_insert_with(|| ProviderEvaluationGroup {
                interface: &binding.interface,
                implementation: &binding.implementation,
                package: binding.provider_package,
                incoming: Vec::new(),
                root: None,
            });
        if group.interface != &binding.interface
            || group.implementation != &binding.implementation
            || group.package != binding.provider_package
        {
            return Err(CompositionError::InvalidFragment {
                provider: binding.provider.clone(),
                reason: "provider aggregate combines different exact package implementations"
                    .to_string(),
            });
        }
        group.incoming.push(binding);
    }
    for selection in enabled_providers {
        let selected_package = desired_state
            .instances
            .iter()
            .find(|desired| desired.enabled && desired.instance == selection.instance)
            .map(|desired| desired.package)
            .ok_or_else(|| CompositionError::MissingImplementation {
                provider: selection.instance.clone(),
            })?;
        let group = groups
            .entry((
                selection.instance.clone(),
                selection.implementation.descriptor,
            ))
            .or_insert_with(|| ProviderEvaluationGroup {
                interface: &selection.interface,
                implementation: &selection.implementation,
                package: Some(selected_package),
                incoming: Vec::new(),
                root: None,
            });
        if group.interface != &selection.interface
            || group.implementation != &selection.implementation
            || group.package != Some(selected_package)
            || group.root.replace(selection).is_some()
        {
            return Err(CompositionError::InvalidFragment {
                provider: selection.instance.clone(),
                reason: "enabled provider selection conflicts with its request-selected aggregate"
                    .to_string(),
            });
        }
    }

    let mut fragments = Vec::new();
    for ((provider, _), group) in groups {
        let reference = group.implementation;
        let incoming = group.incoming;
        let Some(PureImplementation {
            implementation,
            compose_entry,
            aggregation_group,
            activation_mode,
        }) = pure_implementation(&provider, reference, group.package, packages, package_index)?
        else {
            continue;
        };
        let provider_package =
            group
                .package
                .ok_or_else(|| CompositionError::MissingImplementation {
                    provider: provider.clone(),
                })?;
        *evaluations = evaluations.saturating_add(1);
        if *evaluations > limits.max_evaluations {
            return Err(CompositionError::Limit {
                limit: "fragment evaluation count",
            });
        }

        let incoming_requests: Vec<_> = incoming
            .iter()
            .map(|binding| {
                requests.get(&binding.request).copied().ok_or_else(|| {
                    CompositionError::MissingImplementation {
                        provider: provider.clone(),
                    }
                })
            })
            .collect::<Result<_, _>>()?;
        let contributions: Vec<_> = desired_state
            .contributions
            .iter()
            .filter(|contribution| contribution.aggregate.provider == provider)
            .collect();
        if desired_state.outputs.iter().any(|output| {
            !output.value.is_within_limits(
                ABILITY_LIMITS_V1.max_structural_depth,
                ABILITY_LIMITS_V1.max_collection_items,
            )
        }) {
            return Err(CompositionError::Limit {
                limit: "evaluation context structural depth",
            });
        }
        let composition_context = BorrowedCompositionContext {
            schema: "aos.ability.composition-context/v1",
            provider: &provider,
            interface: group.interface,
            implementation: reference,
            package: provider_package,
            requests: incoming_requests,
            bindings,
            contributions,
            resources: &desired_state.resources,
            outputs: &desired_state.outputs,
            controllers: &desired_state.controllers,
        };
        let input = AbilityValue::new(
            serde_json::to_value(composition_context)
                .map_err(|error| CompositionError::Encoding(error.to_string()))?,
        )
        .map_err(|error| CompositionError::Encoding(error.to_string()))?;
        retain_evaluation_bytes(evaluation_bytes, input.encoded_size(), limits)?;
        let output = match evaluator.evaluate(reference, compose_entry, &input) {
            Ok(output) => {
                evaluation_trace.push(CompositionEvaluation {
                    provider: provider.clone(),
                    implementation: reference.clone(),
                    entry: compose_entry.clone(),
                    input: input.clone(),
                    result: CompositionEvaluationResult::Returned {
                        value: output.clone(),
                    },
                });
                output
            }
            Err(source) => {
                let message = bounded_constraint(source.message());
                retain_evaluation_bytes(evaluation_bytes, Ok(message.len() as u64), limits)?;
                evaluation_trace.push(CompositionEvaluation {
                    provider: provider.clone(),
                    implementation: reference.clone(),
                    entry: compose_entry.clone(),
                    input,
                    result: CompositionEvaluationResult::Failed {
                        message: message.clone(),
                    },
                });
                return Err(CompositionError::Evaluation {
                    provider,
                    source: EvaluationError::new(message),
                });
            }
        };
        retain_evaluation_bytes(evaluation_bytes, output.encoded_size(), limits)?;
        let fragment: CompositionFragment =
            serde_json::from_value(output.into_json()).map_err(|error| {
                CompositionError::InvalidFragment {
                    provider: provider.clone(),
                    reason: error.to_string(),
                }
            })?;
        validate_fragment(
            FragmentValidation {
                context,
                provider: &provider,
                reference,
                incoming: &incoming,
                bindings,
                implementation,
                aggregation_group,
                activation_mode,
                root: group.root,
            },
            &fragment,
            limits,
        )?;
        fragments.push((provider, fragment));
    }
    Ok(fragments)
}

#[derive(Serialize)]
struct BorrowedCompositionContext<'a> {
    schema: &'static str,
    provider: &'a InstanceId,
    interface: &'a InterfaceKey,
    implementation: &'a ProviderImplementationReference,
    package: Sha256Digest,
    requests: Vec<&'a BindingRequest>,
    bindings: &'a [Binding],
    contributions: Vec<&'a Contribution>,
    resources: &'a [ResourceRevision],
    outputs: &'a [AggregateOutput],
    controllers: &'a [ControllerAssignment],
}

fn retain_evaluation_bytes(
    retained: &mut u64,
    encoded_size: Result<u64, aos_ability_model::ValueError>,
    limits: CompositionLimits,
) -> Result<(), CompositionError> {
    let encoded_size =
        encoded_size.map_err(|error| CompositionError::Encoding(error.to_string()))?;
    *retained = retained
        .checked_add(encoded_size)
        .ok_or(CompositionError::Limit {
            limit: "aggregate evaluation byte",
        })?;
    if *retained > limits.max_evaluation_bytes {
        return Err(CompositionError::Limit {
            limit: "aggregate evaluation byte",
        });
    }
    Ok(())
}

struct ProviderEvaluationGroup<'a> {
    interface: &'a InterfaceKey,
    implementation: &'a ProviderImplementationReference,
    package: Option<Sha256Digest>,
    incoming: Vec<&'a Binding>,
    root: Option<&'a EnabledProviderSelection>,
}

struct PureImplementation<'a> {
    implementation: &'a ProviderImplementation,
    compose_entry: &'a LocalKey,
    aggregation_group: Option<&'a LocalKey>,
    activation_mode: AbilityActivationMode,
}

fn pure_implementation<'a>(
    provider: &InstanceId,
    reference: &ProviderImplementationReference,
    provider_package: Option<Sha256Digest>,
    packages: &'a [PackageDocument],
    package_index: &BTreeMap<Sha256Digest, usize>,
) -> Result<Option<PureImplementation<'a>>, CompositionError> {
    let Some(provider_package) = provider_package else {
        return if reference.handler.is_some() {
            Ok(None)
        } else {
            Err(CompositionError::MissingImplementation {
                provider: provider.clone(),
            })
        };
    };
    let Some(package_position) = package_index.get(&provider_package) else {
        return Err(CompositionError::MissingImplementation {
            provider: provider.clone(),
        });
    };
    let package = &packages[*package_position];
    let implementation = package
        .implementation
        .providers
        .iter()
        .find(|implementation| {
            implementation.artifact == reference.artifact
                && implementation
                    .descriptor_digest()
                    .is_ok_and(|descriptor| descriptor == reference.descriptor)
        });
    let Some(implementation) = implementation else {
        return if reference.handler.is_some() {
            Ok(None)
        } else {
            Err(CompositionError::MissingImplementation {
                provider: provider.clone(),
            })
        };
    };
    let aggregation_group = package
        .exports
        .iter()
        .find(|export| {
            export.interface == implementation.interface
                && export.implementation == reference.descriptor
        })
        .and_then(|export| export.aggregation.as_ref())
        .map(|aggregation| &aggregation.controller_group);
    match &implementation.implementation {
        ImplementationKind::PureComposition {
            compose_entry,
            transition_entry,
        } if reference.handler.is_none()
            && package.module_entry_points.get(compose_entry) == Some(&reference.artifact)
            && package.module_entry_points.get(transition_entry) == Some(&reference.artifact) =>
        {
            Ok(Some(PureImplementation {
                implementation,
                compose_entry,
                aggregation_group,
                activation_mode: package.activation_mode,
            }))
        }
        ImplementationKind::PureComposition { .. } => {
            Err(CompositionError::MissingImplementation {
                provider: provider.clone(),
            })
        }
        ImplementationKind::TerminalHandler { .. } => Ok(None),
    }
}

struct FragmentValidation<'a> {
    context: &'a ValidationContext,
    provider: &'a InstanceId,
    reference: &'a ProviderImplementationReference,
    incoming: &'a [&'a Binding],
    bindings: &'a [Binding],
    implementation: &'a ProviderImplementation,
    aggregation_group: Option<&'a LocalKey>,
    activation_mode: AbilityActivationMode,
    root: Option<&'a EnabledProviderSelection>,
}

fn validate_fragment(
    validation: FragmentValidation<'_>,
    fragment: &CompositionFragment,
    limits: CompositionLimits,
) -> Result<(), CompositionError> {
    let FragmentValidation {
        context,
        provider,
        reference,
        incoming,
        bindings,
        implementation,
        aggregation_group,
        activation_mode,
        root,
    } = validation;
    let invalid = |reason: &str| CompositionError::InvalidFragment {
        provider: provider.clone(),
        reason: reason.to_string(),
    };
    if fragment.schema != "aos.ability.composition-fragment/v1" {
        return Err(invalid("unsupported fragment schema"));
    }
    if activation_mode == AbilityActivationMode::ContractsOnly
        && (!fragment.resources.is_empty() || !fragment.controllers.is_empty())
    {
        return Err(invalid(
            "contracts-only provider emits resource ownership or lifecycle controllers",
        ));
    }
    if incoming
        .iter()
        .any(|binding| binding.implementation != *reference)
    {
        return Err(invalid(
            "provider group contains different implementation references",
        ));
    }
    let child_scope = child_request_id(provider, provider.key.clone())?.scope;

    if fragment
        .requests
        .windows(2)
        .any(|pair| compare_request_ids(&pair[0].id, &pair[1].id) != std::cmp::Ordering::Less)
    {
        return Err(invalid(
            "fragment requests are not in strict canonical order",
        ));
    }
    let requirements: BTreeMap<_, _> = implementation
        .requirements
        .iter()
        .map(|requirement| (&requirement.alias, requirement))
        .collect();
    let mut supplied = BTreeSet::new();
    let maximum_lifetime = incoming
        .iter()
        .map(|binding| binding.lifetime)
        .chain(root.map(|selection| selection.lifetime))
        .max()
        .ok_or_else(|| invalid("provider group has no lifetime"))?;
    for request in &fragment.requests {
        validate_child_depth(provider, &request.id, limits)?;
        let Some(requirement) = requirements.get(&request.id.key) else {
            return Err(invalid(
                "fragment emits an undeclared lower-interface request",
            ));
        };
        if request.id.consumer != *provider
            || request.id.scope != child_scope
            || request.accepted_interfaces != requirement.accepted_interfaces
            || request.methods != requirement.methods
            || request.guarantees != requirement.guarantees
            || request.lifetime > maximum_lifetime
        {
            return Err(invalid(
                "fragment request differs from its declared alias, scope, interface, methods, guarantees, or lifetime authority",
            ));
        }
        supplied.insert(request.id.key.clone());
    }
    if implementation.requirements.iter().any(|requirement| {
        requirement.strength == aos_ability_model::RequirementStrength::Required
            && !supplied.contains(&requirement.alias)
    }) {
        return Err(invalid(
            "fragment omits a required implementation requirement",
        ));
    }

    if fragment.resources.windows(2).any(|pair| {
        compare_resource_ids(&pair[0].resource, &pair[1].resource) != std::cmp::Ordering::Less
    }) || fragment
        .resources
        .iter()
        .any(|revision| revision.resource.provider != *provider)
    {
        return Err(invalid(
            "fragment resources are noncanonical or outside the provider's ownership scope",
        ));
    }
    if let Some(selection) = root {
        for revision in &fragment.resources {
            let authorized = selection.provider_grant.resources.iter().any(|permission| {
                permission.resource == revision.resource && permission.access.is_write()
            });
            if !authorized {
                return Err(invalid(
                    "root provider resource exceeds its authenticated implementation grant",
                ));
            }
        }
    }
    let resource_ids: BTreeSet<_> = fragment
        .resources
        .iter()
        .map(|revision| &revision.resource)
        .collect();
    if fragment.controllers.windows(2).any(|pair| {
        compare_resource_ids(&pair[0].resource, &pair[1].resource) != std::cmp::Ordering::Less
    }) || fragment.controllers.iter().any(|assignment| {
        !resource_ids.contains(&assignment.resource) || assignment.controller.provider != *provider
    }) {
        return Err(invalid(
            "fragment controllers are noncanonical or do not own a fragment resource",
        ));
    }
    let child_requests: BTreeSet<_> = fragment
        .requests
        .iter()
        .map(|request| &request.id)
        .collect();
    if fragment.contributions.iter().any(|contribution| {
        !child_requests.contains(&contribution.request)
            || contribution.request.consumer != *provider
            || contribution.aggregate.provider.environment != provider.environment
    }) {
        return Err(invalid(
            "fragment contribution lacks a declared child request or leaves the environment",
        ));
    }
    let Some(interface) = context.interface(&implementation.interface) else {
        return Err(invalid(
            "provider interface is absent from the validated catalog",
        ));
    };
    if fragment
        .outputs
        .windows(2)
        .any(|pair| aggregate_output_key(&pair[0]) >= aggregate_output_key(&pair[1]))
    {
        return Err(invalid(
            "fragment outputs are not in strict provider-qualified canonical order",
        ));
    }
    if fragment.outputs.iter().any(|output| {
        output.aggregate.provider != *provider
            || aggregation_group != Some(&output.aggregate.group)
            || output.interface != implementation.interface
            || !interface.interface.outputs.contains_key(&output.port)
    }) {
        return Err(invalid(
            "fragment emits an unqualified or undeclared provider output",
        ));
    }
    for output in &fragment.outputs {
        let descriptor = &interface.interface.outputs[&output.port];
        if descriptor.phase > ValuePhase::Planning {
            return Err(invalid(
                "pure composition output declares an admission or runtime-only phase",
            ));
        }
    }
    for contribution in &fragment.contributions {
        let authorized = bindings.iter().any(|binding| {
            binding.id == contribution.grant
                && binding.request == contribution.request
                && binding.provider == contribution.aggregate.provider
                && binding.caller_grant.contributions.iter().any(|permission| {
                    permission.aggregate == contribution.aggregate
                        && permission.slot == contribution.slot
                })
        });
        if !authorized {
            return Err(invalid(
                "fragment contribution is not authorized by an exact selected caller grant",
            ));
        }
    }
    Ok(())
}

fn aggregate_output_key(
    output: &AggregateOutput,
) -> (
    &aos_ability_model::AggregateId,
    &aos_ability_model::InterfaceKey,
    &LocalKey,
) {
    (&output.aggregate, &output.interface, &output.port)
}

pub(super) fn validate_desired_outputs(
    context: &ValidationContext,
    desired_state: &DesiredStateDocument,
    bindings: &[Binding],
    resources: &[ResourceRevision],
    packages: &[PackageDocument],
    package_index: &BTreeMap<Sha256Digest, usize>,
    enabled_providers: &[EnabledProviderSelection],
) -> Result<(), CompositionError> {
    for output in &desired_state.outputs {
        let artifacts = provider_artifacts(
            &output.aggregate.provider,
            desired_state,
            packages,
            package_index,
        );
        context
            .validate_composed_output(
                &output.aggregate.provider,
                output,
                &desired_state.outputs,
                bindings,
                resources,
                &artifacts,
                enabled_providers
                    .iter()
                    .find(|selection| {
                        selection.instance == output.aggregate.provider
                            && selection.interface == output.interface
                    })
                    .map(|selection| (&selection.provider_grant, selection.lifetime)),
            )
            .map_err(|error| CompositionError::InvalidFragment {
                provider: output.aggregate.provider.clone(),
                reason: error.to_string(),
            })?;
    }
    Ok(())
}

pub(super) fn validate_desired_activation_modes(
    desired_state: &DesiredStateDocument,
    packages: &[PackageDocument],
    package_index: &BTreeMap<Sha256Digest, usize>,
) -> Result<(), CompositionError> {
    for provider in desired_state
        .resources
        .iter()
        .map(|revision| &revision.resource.provider)
        .chain(
            desired_state
                .controllers
                .iter()
                .map(|assignment| &assignment.controller.provider),
        )
    {
        let package = desired_state
            .instances
            .iter()
            .find(|desired| desired.instance == *provider)
            .and_then(|desired| package_index.get(&desired.package))
            .map(|position| &packages[*position]);
        if package
            .is_some_and(|package| package.activation_mode == AbilityActivationMode::ContractsOnly)
        {
            return Err(CompositionError::InvalidFragment {
                provider: provider.clone(),
                reason: "desired resource or controller is attributed to a contracts-only package"
                    .to_string(),
            });
        }
    }
    Ok(())
}

pub(super) fn validate_enabled_providers(
    context: &ValidationContext,
    policy: &ResolutionPolicyDocument,
    desired_state: &DesiredStateDocument,
    packages: &[PackageDocument],
    package_index: &BTreeMap<Sha256Digest, usize>,
) -> Result<(), CompositionError> {
    for desired in desired_state
        .instances
        .iter()
        .filter(|desired| desired.enabled)
    {
        let package = package_index
            .get(&desired.package)
            .map(|position| &packages[*position])
            .ok_or_else(|| CompositionError::MissingImplementation {
                provider: desired.instance.clone(),
            })?;
        let has_pure_aggregate = package
            .implementation
            .providers
            .iter()
            .any(|implementation| {
                matches!(
                    implementation.implementation,
                    ImplementationKind::PureComposition { .. }
                ) && implementation.descriptor_digest().is_ok_and(|descriptor| {
                    package.exports.iter().any(|export| {
                        export.interface == implementation.interface
                            && export.implementation == descriptor
                            && export.aggregation.is_some()
                    })
                })
            });
        if has_pure_aggregate
            && !policy
                .enabled_providers
                .iter()
                .any(|selection| selection.instance == desired.instance)
        {
            return Err(CompositionError::MissingImplementation {
                provider: desired.instance.clone(),
            });
        }
    }

    for selection in &policy.enabled_providers {
        let desired = desired_state
            .instances
            .iter()
            .find(|desired| desired.enabled && desired.instance == selection.instance)
            .ok_or_else(|| CompositionError::MissingImplementation {
                provider: selection.instance.clone(),
            })?;
        let package = package_index
            .get(&desired.package)
            .map(|position| &packages[*position])
            .ok_or_else(|| CompositionError::MissingImplementation {
                provider: selection.instance.clone(),
            })?;
        let implementation = package
            .implementation
            .providers
            .iter()
            .find(|implementation| {
                implementation.interface == selection.interface
                    && implementation.artifact == selection.implementation.artifact
                    && implementation
                        .descriptor_digest()
                        .is_ok_and(|digest| digest == selection.implementation.descriptor)
            })
            .ok_or_else(|| CompositionError::MissingImplementation {
                provider: selection.instance.clone(),
            })?;
        let exported = package.exports.iter().any(|export| {
            export.interface == selection.interface
                && export.implementation == selection.implementation.descriptor
                && export.aggregation.is_some()
        });
        let valid_entry = match &implementation.implementation {
            ImplementationKind::PureComposition {
                compose_entry,
                transition_entry,
            } => {
                selection.implementation.handler.is_none()
                    && package.module_entry_points.get(compose_entry)
                        == Some(&selection.implementation.artifact)
                    && package.module_entry_points.get(transition_entry)
                        == Some(&selection.implementation.artifact)
            }
            ImplementationKind::TerminalHandler { .. } => false,
        };
        let methods_valid = context
            .interface(&selection.interface)
            .is_some_and(|interface| {
                selection
                    .provider_grant
                    .methods
                    .iter()
                    .all(|method| interface.interface.methods.contains_key(method))
            });
        if !exported || !valid_entry || !methods_valid {
            return Err(CompositionError::MissingImplementation {
                provider: selection.instance.clone(),
            });
        }
    }
    Ok(())
}

fn provider_artifacts(
    provider: &InstanceId,
    desired_state: &DesiredStateDocument,
    packages: &[PackageDocument],
    package_index: &BTreeMap<Sha256Digest, usize>,
) -> Vec<ArtifactReference> {
    let Some(package) = desired_state
        .instances
        .iter()
        .find(|instance| instance.enabled && instance.instance == *provider)
        .and_then(|instance| package_index.get(&instance.package))
        .map(|index| &packages[*index])
    else {
        return Vec::new();
    };
    let mut artifacts = package.artifacts.clone();
    artifacts.push(package.package.payload.clone());
    artifacts.push(package.package.source.clone());
    artifacts.extend(package.module_entry_points.values().cloned());
    artifacts
}
