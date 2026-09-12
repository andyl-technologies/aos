//! Checked provider-owner and terminal-handler selection.

use std::collections::BTreeMap;

use aos_ability_model::document::ProviderState;
use aos_ability_model::{
    ArtifactReference, Binding, BindingId, ImplementationKind, InstanceId, InterfaceName, LocalKey,
    Operation, PackageDocument, ProviderAdoptionAuthorization, ProviderImplementation, ResourceId,
    ResourceLifetime, VersionedDocument,
};
use aos_ability_validate::{BindingAuthorityKind, CheckedEffectPlan};

use super::super::{GenerationAbilityStoreError, canonical_artifacts};
use super::records::{NativeProviderHandlerIdentity, NativeProviderIdentity};

/// Records one complete durable-owner endpoint selected by the desired plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::config_eval::ability_store::inventory) struct NativeProviderSelection {
    /// Identifies the persistent resource retained by the selection.
    pub(in crate::config_eval::ability_store::inventory) resource: ResourceId,
    /// Pins the selected stateful composition implementation.
    pub(in crate::config_eval::ability_store::inventory) identity: NativeProviderIdentity,
    /// Pins the selected, available terminal handler endpoint.
    pub(in crate::config_eval::ability_store::inventory) handler: NativeProviderHandlerIdentity,
}

/// Collects the unique durable-owner and handler selections in a checked plan.
///
/// # Errors
///
/// Returns an error when package or implementation identity is ambiguous or
/// cannot be authenticated from the checked plan.
pub(in crate::config_eval::ability_store::inventory) fn selected_provider_owners(
    plan: &CheckedEffectPlan,
) -> Result<Vec<NativeProviderSelection>, GenerationAbilityStoreError> {
    let binding_plan = plan.binding_plan();
    let mut selections = Vec::new();

    for owner_binding in binding_plan.bindings().iter().filter(|binding| {
        binding_plan.binding_authority(&binding.id) == Some(&BindingAuthorityKind::Desired)
    }) {
        let Some((identity, owned_kinds)) = selected_owner_identity(binding_plan, owner_binding)?
        else {
            continue;
        };

        for handler_binding in binding_plan.bindings().iter().filter(|binding| {
            binding_plan.binding_authority(&binding.id) == Some(&BindingAuthorityKind::Desired)
        }) {
            let Some((handler, methods)) =
                selected_owner_handler(plan, handler_binding, &identity, &owned_kinds)?
            else {
                continue;
            };

            for permission in &handler_binding.caller_grant.resources {
                if !permission.access.is_write() {
                    continue;
                }
                if methods
                    .iter()
                    .any(|method| permission.operations.contains(method))
                {
                    let selection = NativeProviderSelection {
                        resource: permission.resource.clone(),
                        identity: identity.clone(),
                        handler: handler.clone(),
                    };
                    if !selections.contains(&selection) {
                        selections.push(selection);
                    }
                }
            }
        }
    }

    unique_provider_owner_selections(selections)
}

/// Collects stateful owner selections from an independently checked prior plan.
///
/// # Errors
///
/// Returns an error when retained package, implementation, or assignment
/// identity is ambiguous or inconsistent.
pub(in crate::config_eval::ability_store::inventory) fn selected_retained_provider_owners(
    binding_plan: &aos_ability_validate::CheckedBindingPlan,
) -> Result<Vec<NativeProviderSelection>, GenerationAbilityStoreError> {
    let mut selections = Vec::new();
    for owner_binding in binding_plan.bindings() {
        let Some((identity, _)) = selected_owner_identity(binding_plan, owner_binding)? else {
            continue;
        };
        for handler_binding in binding_plan.bindings() {
            let Some(handler) = retained_owner_handler(binding_plan, handler_binding, &identity)?
            else {
                continue;
            };
            for permission in &handler_binding.caller_grant.resources {
                if permission.access.is_write() && permission.resource.provider == identity.provider
                {
                    selections.push(NativeProviderSelection {
                        resource: permission.resource.clone(),
                        identity: identity.clone(),
                        handler: handler.clone(),
                    });
                }
            }
        }
    }
    unique_provider_owner_selections(selections)
}

/// Resolves one exact prior owner through a checked teardown source binding.
///
/// # Errors
///
/// Returns an error when prior owner, handler, package, or assignment evidence
/// is ambiguous or inconsistent.
pub(in crate::config_eval::ability_store::inventory) fn retained_provider_owner_for_teardown(
    binding_plan: &aos_ability_validate::CheckedBindingPlan,
    source_binding: &BindingId,
    resource: &ResourceId,
) -> Result<Option<NativeProviderSelection>, GenerationAbilityStoreError> {
    let Some(handler_binding) = binding_plan.binding(source_binding) else {
        return Ok(None);
    };
    let Some(request) = binding_plan
        .document()
        .requests
        .iter()
        .find(|request| request.id == handler_binding.request)
    else {
        return Ok(None);
    };
    if !handler_binding
        .caller_grant
        .resources
        .iter()
        .chain(&handler_binding.provider_grant.resources)
        .any(|permission| permission.resource == *resource)
    {
        return Ok(None);
    }
    let mut owners = Vec::new();
    for binding in binding_plan
        .bindings()
        .iter()
        .filter(|binding| binding.provider == request.id.consumer)
    {
        if let Some((identity, _)) = selected_owner_identity(binding_plan, binding)?
            && !owners.contains(&identity)
        {
            owners.push(identity);
        }
    }
    let [owner] = owners.as_slice() else {
        return if owners.is_empty() {
            Ok(None)
        } else {
            Err(GenerationAbilityStoreError::Conflict(
                "retained teardown resource has ambiguous durable owner identity".to_string(),
            ))
        };
    };
    let Some(handler) = retained_owner_handler(binding_plan, handler_binding, owner)? else {
        return Ok(None);
    };
    Ok(Some(NativeProviderSelection {
        resource: resource.clone(),
        identity: owner.clone(),
        handler,
    }))
}

fn retained_owner_handler(
    binding_plan: &aos_ability_validate::CheckedBindingPlan,
    binding: &Binding,
    owner: &NativeProviderIdentity,
) -> Result<Option<NativeProviderHandlerIdentity>, GenerationAbilityStoreError> {
    let Some(request) = binding_plan
        .document()
        .requests
        .iter()
        .find(|request| request.id == binding.request)
    else {
        return Ok(None);
    };
    if request.id.consumer != owner.provider
        || request.lifetime != ResourceLifetime::Persistent
        || binding.lifetime != ResourceLifetime::Persistent
    {
        return Ok(None);
    }
    let Some(package_digest) = binding.provider_package else {
        return Ok(None);
    };
    let Some(package) = exact_package(binding_plan.packages(), package_digest)? else {
        return Ok(None);
    };
    let Some(implementation) = exact_provider_implementation(package, binding)? else {
        return Ok(None);
    };
    if !matches!(
        implementation.implementation,
        ImplementationKind::TerminalHandler { .. }
    ) {
        return Ok(None);
    }
    let assignments = binding_plan
        .environment()
        .providers
        .iter()
        .filter(|provider| {
            provider.provider == binding.provider
                && provider.interface == binding.interface
                && provider.implementation == binding.implementation
                && provider.state == ProviderState::Available
                && provider.incarnation.is_some()
        })
        .collect::<Vec<_>>();
    let [assignment] = assignments.as_slice() else {
        return Ok(None);
    };
    Ok(Some(NativeProviderHandlerIdentity {
        package: package_digest,
        provider: assignment.provider.clone(),
        interface: assignment.interface.clone(),
        implementation: assignment.implementation.clone(),
    }))
}

pub(in crate::config_eval::ability_store) fn unique_provider_owner_selections(
    selections: Vec<NativeProviderSelection>,
) -> Result<Vec<NativeProviderSelection>, GenerationAbilityStoreError> {
    let mut by_resource = BTreeMap::new();
    for selection in selections {
        match by_resource.insert(selection.resource.clone(), selection.clone()) {
            Some(previous) if previous != selection => {
                return Err(GenerationAbilityStoreError::Conflict(
                    "stateful native resource selects multiple durable handler implementations"
                        .to_string(),
                ));
            }
            _ => {}
        }
    }

    Ok(by_resource.into_values().collect())
}

fn selected_owner_identity(
    binding_plan: &aos_ability_validate::CheckedBindingPlan,
    binding: &Binding,
) -> Result<Option<(NativeProviderIdentity, Vec<InterfaceName>)>, GenerationAbilityStoreError> {
    if binding.lifetime != ResourceLifetime::Persistent {
        return Ok(None);
    }
    let Some(package_digest) = binding.provider_package else {
        return Ok(None);
    };
    let Some(package) = exact_package(binding_plan.packages(), package_digest)? else {
        return Ok(None);
    };
    let Some(implementation) = exact_provider_implementation(package, binding)? else {
        return Ok(None);
    };
    let Some(state_format) = implementation.state_format.clone() else {
        return Ok(None);
    };
    if !matches!(
        implementation.implementation,
        ImplementationKind::PureComposition { .. }
    ) || implementation.owns_resource_kinds.is_empty()
        || state_format.artifact != implementation.artifact
    {
        return Ok(None);
    }

    Ok(Some((
        NativeProviderIdentity {
            provider: binding.provider.clone(),
            package: package_digest,
            interface: binding.interface.clone(),
            implementation: binding.implementation.clone(),
            state_format,
        },
        implementation.owns_resource_kinds.clone(),
    )))
}

fn selected_owner_handler(
    plan: &CheckedEffectPlan,
    binding: &Binding,
    owner: &NativeProviderIdentity,
    owned_kinds: &[InterfaceName],
) -> Result<Option<(NativeProviderHandlerIdentity, Vec<LocalKey>)>, GenerationAbilityStoreError> {
    let binding_plan = plan.binding_plan();
    let Some(request) = binding_plan
        .document()
        .requests
        .iter()
        .find(|request| request.id == binding.request)
    else {
        return Ok(None);
    };
    if request.id.consumer != owner.provider
        || request.id.scope.as_slice().first() != Some(&owner.provider.key)
        || request.lifetime != ResourceLifetime::Persistent
        || binding.lifetime != ResourceLifetime::Persistent
    {
        return Ok(None);
    }

    let Some(package_digest) = binding.provider_package else {
        return Ok(None);
    };
    let Some(package) = exact_package(binding_plan.packages(), package_digest)? else {
        return Ok(None);
    };
    let Some(implementation) = exact_provider_implementation(package, binding)? else {
        return Ok(None);
    };
    let ImplementationKind::TerminalHandler { handler } = &implementation.implementation else {
        return Ok(None);
    };
    if binding.implementation.handler.as_ref() != Some(handler)
        || !package
            .implementation
            .handlers
            .get(handler)
            .is_some_and(|descriptor| descriptor.artifact == binding.implementation.artifact)
    {
        return Ok(None);
    }

    let assignments = binding_plan
        .environment()
        .providers
        .iter()
        .filter(|provider| {
            provider.provider == binding.provider
                && provider.interface == binding.interface
                && provider.implementation == binding.implementation
                && provider.state == ProviderState::Available
                && provider.incarnation.is_some()
        })
        .collect::<Vec<_>>();
    let [assignment] = assignments.as_slice() else {
        return Ok(None);
    };
    let methods = request
        .methods
        .iter()
        .filter(|method| binding.caller_grant.methods.contains(method))
        .filter(|method| {
            plan.interfaces()
                .get(&binding.interface)
                .and_then(|interface| interface.interface.methods.get(*method))
                .is_some_and(|descriptor| owned_kinds.contains(&descriptor.target_resource))
        })
        .cloned()
        .collect::<Vec<_>>();
    if methods.is_empty() {
        return Ok(None);
    }

    Ok(Some((
        NativeProviderHandlerIdentity {
            package: package_digest,
            provider: assignment.provider.clone(),
            interface: assignment.interface.clone(),
            implementation: assignment.implementation.clone(),
        },
        methods,
    )))
}

fn exact_package(
    packages: &[PackageDocument],
    digest: aos_contract::Sha256Digest,
) -> Result<Option<&PackageDocument>, GenerationAbilityStoreError> {
    let mut matching = Vec::new();
    for package in packages {
        let candidate = package.content_digest().map_err(|error| {
            GenerationAbilityStoreError::Conflict(format!(
                "selected native owner package cannot be authenticated: {error}"
            ))
        })?;
        if candidate == digest {
            matching.push(package);
        }
    }
    match matching.as_slice() {
        [] => Ok(None),
        [package] => Ok(Some(*package)),
        _ => Err(GenerationAbilityStoreError::Conflict(
            "selected native owner package identity is ambiguous".to_string(),
        )),
    }
}

fn exact_provider_implementation<'a>(
    package: &'a PackageDocument,
    binding: &Binding,
) -> Result<Option<&'a ProviderImplementation>, GenerationAbilityStoreError> {
    let mut matching = Vec::new();
    for implementation in &package.implementation.providers {
        let descriptor = implementation.descriptor_digest().map_err(|error| {
            GenerationAbilityStoreError::Conflict(format!(
                "selected native owner implementation cannot be authenticated: {error}"
            ))
        })?;
        if implementation.interface == binding.interface
            && implementation.artifact == binding.implementation.artifact
            && descriptor == binding.implementation.descriptor
            && package.exports.iter().any(|export| {
                export.interface == implementation.interface && export.implementation == descriptor
            })
        {
            matching.push(implementation);
        }
    }
    match matching.as_slice() {
        [] => Ok(None),
        [implementation] => Ok(Some(*implementation)),
        _ => Err(GenerationAbilityStoreError::Conflict(
            "selected native owner implementation identity is ambiguous".to_string(),
        )),
    }
}

/// Resolves the durable owner identity admitted for one checked operation.
///
/// # Errors
///
/// Returns an error when the operation loses its checked binding or when its
/// package, implementation, or adoption endpoint is ambiguous.
pub(in crate::config_eval::ability_store::inventory) fn operation_provider_identity(
    plan: &CheckedEffectPlan,
    operation: &Operation,
    adoptions: &[ProviderAdoptionAuthorization],
) -> Result<
    Option<(NativeProviderIdentity, NativeProviderHandlerIdentity)>,
    GenerationAbilityStoreError,
> {
    let binding = plan
        .binding_plan()
        .binding(&operation.binding)
        .ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "native owner operation lost its checked binding".to_string(),
            )
        })?;
    let binding_authority = plan
        .binding_plan()
        .binding_authority(&operation.binding)
        .ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "native owner operation lost its checked binding authority".to_string(),
            )
        })?;
    let matching_endpoints = adoptions
        .iter()
        .filter(|adoption| {
            adoption.resource == operation.target.resource
                && adoption.resource_interface == operation.target.interface
        })
        .filter_map(|adoption| match binding_authority {
            BindingAuthorityKind::Desired => Some((&adoption.candidate, &operation.binding, true)),
            BindingAuthorityKind::Teardown { source_binding, .. } => {
                Some((&adoption.source, source_binding, false))
            }
        })
        .filter(|(endpoint, endpoint_binding, require_method)| {
            endpoint_matches_selected_owner(
                plan.binding_plan().bindings(),
                binding,
                operation,
                endpoint,
                endpoint_binding,
                *require_method,
            )
        })
        .map(|(endpoint, _, _)| endpoint)
        .collect::<Vec<_>>();
    if matching_endpoints.len() > 1 {
        return Err(GenerationAbilityStoreError::Conflict(
            "native owner operation matches ambiguous adoption endpoints".to_string(),
        ));
    }
    if let Some(endpoint) = matching_endpoints.first() {
        return Ok(Some((
            NativeProviderIdentity::from_endpoint(endpoint),
            handler_from_endpoint(endpoint),
        )));
    }

    let resource_selections = selected_provider_owners(plan)?
        .into_iter()
        .filter(|selection| selection.resource == operation.target.resource)
        .collect::<Vec<_>>();
    let matching_selections = if resource_selections.is_empty() {
        Vec::new()
    } else {
        let handler = checked_handler_identity(plan, operation)?;
        resource_selections
            .into_iter()
            .filter(|selection| selection.handler == handler)
            .collect::<Vec<_>>()
    };
    match matching_selections.as_slice() {
        [selection] => {
            return Ok(Some((
                selection.identity.clone(),
                selection.handler.clone(),
            )));
        }
        [] => {}
        _ => {
            return Err(GenerationAbilityStoreError::Conflict(
                "native owner operation matches ambiguous durable owner selections".to_string(),
            ));
        }
    }

    let Some(owner) = operation_provider_owner(binding, operation) else {
        return Ok(None);
    };

    let mut identities = Vec::new();
    for selected in plan
        .binding_plan()
        .bindings()
        .iter()
        .filter(|selected| selected.provider == *owner)
    {
        let Some(package_digest) = selected.provider_package else {
            continue;
        };
        let mut packages = plan.binding_plan().packages().iter().filter(|package| {
            package
                .content_digest()
                .is_ok_and(|digest| digest == package_digest)
        });
        let Some(package) = packages.next() else {
            continue;
        };
        if packages.next().is_some() {
            return Err(GenerationAbilityStoreError::Conflict(
                "native owner package identity is ambiguous".to_string(),
            ));
        }

        let mut implementations = package.implementation.providers.iter().filter(|candidate| {
            matches!(
                candidate.implementation,
                ImplementationKind::PureComposition { .. }
            ) && candidate.interface == selected.interface
                && candidate.artifact == selected.implementation.artifact
                && candidate
                    .descriptor_digest()
                    .is_ok_and(|descriptor| descriptor == selected.implementation.descriptor)
                && package.exports.iter().any(|export| {
                    export.interface == candidate.interface
                        && export.implementation == selected.implementation.descriptor
                })
                && candidate
                    .owns_resource_kinds
                    .contains(&operation.target.interface.name)
                && candidate
                    .state_format
                    .as_ref()
                    .is_some_and(|format| format.artifact == candidate.artifact)
        });
        let Some(implementation) = implementations.next() else {
            continue;
        };
        if implementations.next().is_some() {
            return Err(GenerationAbilityStoreError::Conflict(
                "native owner implementation identity is ambiguous".to_string(),
            ));
        }
        let state_format = implementation.state_format.clone().ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "native owner implementation lost its state-format declaration".to_string(),
            )
        })?;
        let identity = NativeProviderIdentity {
            provider: owner.clone(),
            package: package_digest,
            interface: implementation.interface.clone(),
            implementation: selected.implementation.clone(),
            state_format,
        };
        if !identities.contains(&identity) {
            identities.push(identity);
        }
    }

    match identities.as_slice() {
        [] => Ok(None),
        [identity] => Ok(Some((
            identity.clone(),
            checked_handler_identity(plan, operation)?,
        ))),
        _ => Err(GenerationAbilityStoreError::Conflict(
            "native owner implementation identity is ambiguous".to_string(),
        )),
    }
}

/// Reports whether an adoption endpoint exactly matches the selected owner and
/// terminal handler for an operation.
pub(in crate::config_eval::ability_store::inventory) fn endpoint_matches_selected_owner(
    selected_bindings: &[Binding],
    handler_binding: &Binding,
    operation: &Operation,
    endpoint: &aos_ability_model::ProviderAdoptionEndpoint,
    endpoint_binding: &BindingId,
    require_endpoint_method: bool,
) -> bool {
    endpoint.provider == handler_binding.request.consumer
        && (!require_endpoint_method
            || selected_bindings.iter().any(|selected| {
                selected.provider == endpoint.provider
                    && selected.provider_package == Some(endpoint.package)
                    && selected.interface == endpoint.interface
                    && selected.implementation == endpoint.implementation
            }))
        && endpoint.handler_binding == *endpoint_binding
        && (!require_endpoint_method || endpoint.handler_method == operation.method)
        && endpoint.handler_provider == handler_binding.provider
        && endpoint.handler_interface == handler_binding.interface
        && endpoint.handler_implementation == handler_binding.implementation
        && Some(endpoint.handler_package) == handler_binding.provider_package
}

/// Reconstructs the exact checked terminal-handler identity for an operation.
///
/// # Errors
///
/// Returns an error when the binding, package, or unique available provider
/// incarnation committed by the checked plan is absent.
pub(in crate::config_eval::ability_store::inventory) fn checked_handler_identity(
    plan: &CheckedEffectPlan,
    operation: &Operation,
) -> Result<NativeProviderHandlerIdentity, GenerationAbilityStoreError> {
    let binding = plan
        .binding_plan()
        .binding(&operation.binding)
        .ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "native owner operation lost its checked handler binding".to_string(),
            )
        })?;
    let matching = plan
        .binding_plan()
        .environment()
        .providers
        .iter()
        .filter(|provider| {
            provider.provider == binding.provider
                && provider.interface == binding.interface
                && provider.implementation == binding.implementation
                && provider.state == ProviderState::Available
                && provider.incarnation.is_some()
        })
        .collect::<Vec<_>>();
    let [provider] = matching.as_slice() else {
        return Err(GenerationAbilityStoreError::Conflict(
            "native owner operation lacks one exact checked handler assignment".to_string(),
        ));
    };
    Ok(NativeProviderHandlerIdentity {
        package: binding.provider_package.ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "checked native handler assignment lost its package".to_string(),
            )
        })?,
        provider: provider.provider.clone(),
        interface: provider.interface.clone(),
        implementation: provider.implementation.clone(),
    })
}

/// Returns the provider instance that owns an operation's logical resource.
pub(in crate::config_eval::ability_store::inventory) fn operation_provider_owner<'a>(
    binding: &'a Binding,
    operation: &Operation,
) -> Option<&'a InstanceId> {
    (operation.target.resource.provider == binding.request.consumer)
        .then_some(&binding.request.consumer)
}

impl NativeProviderIdentity {
    /// Copies the durable owner identity sealed in an adoption endpoint.
    pub(in crate::config_eval::ability_store::inventory) fn from_endpoint(
        endpoint: &aos_ability_model::ProviderAdoptionEndpoint,
    ) -> Self {
        Self {
            provider: endpoint.provider.clone(),
            package: endpoint.package,
            interface: endpoint.interface.clone(),
            implementation: endpoint.implementation.clone(),
            state_format: endpoint.state_format.clone(),
        }
    }
}

/// Copies the terminal provider assignment sealed in an adoption endpoint.
#[cfg(test)]
pub(in crate::config_eval::ability_store::inventory) fn assignment_from_endpoint(
    endpoint: &aos_ability_model::ProviderAdoptionEndpoint,
) -> aos_ability_model::ProviderAssignment {
    aos_ability_model::ProviderAssignment {
        provider: endpoint.handler_provider.clone(),
        interface: endpoint.handler_interface.clone(),
        implementation: endpoint.handler_implementation.clone(),
        incarnation: endpoint.handler_incarnation.clone(),
    }
}

/// Copies the complete terminal handler identity sealed in an adoption endpoint.
pub(in crate::config_eval::ability_store::inventory) fn handler_from_endpoint(
    endpoint: &aos_ability_model::ProviderAdoptionEndpoint,
) -> NativeProviderHandlerIdentity {
    NativeProviderHandlerIdentity {
        package: endpoint.handler_package,
        provider: endpoint.handler_provider.clone(),
        interface: endpoint.handler_interface.clone(),
        implementation: endpoint.handler_implementation.clone(),
    }
}

/// Returns the canonical owner and handler artifacts retained by an endpoint.
///
/// # Errors
///
/// Returns an error when either artifact is invalid or the pair cannot be
/// canonicalized without conflicting identities.
pub(in crate::config_eval::ability_store::inventory) fn artifacts_from_endpoint(
    endpoint: &aos_ability_model::ProviderAdoptionEndpoint,
) -> Result<Vec<ArtifactReference>, GenerationAbilityStoreError> {
    canonical_artifacts(&[
        endpoint.implementation.artifact.clone(),
        endpoint.handler_implementation.artifact.clone(),
    ])
}
