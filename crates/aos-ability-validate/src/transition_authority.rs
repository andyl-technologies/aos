//! Validation and sealing of fresh authority used while retiring prior state.

use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::document::ProviderState;
use aos_ability_model::{
    AccessMode, Binding, BindingId, PROVIDER_STATE_ADOPTION_FEATURE, PackageDocument, PlanId,
    ProviderAdoptionEndpoint, ProviderImplementation, ResourceLifetime, RevisionId,
    TransitionAuthorizationDocument, VersionedDocument, encode_canonical,
};
use aos_contract::Sha256Digest;
use thiserror::Error;

use crate::graph::{BindingProviderState, BindingValidationInputs, CheckedBindingPlan};
use crate::{BindingAuthorityKind, ValidationContext};

/// Supplies external commitments and sealed plans used to check transition authority.
pub struct TransitionAuthorityInputs<'a> {
    /// Supplies the independently authenticated authorization commitment.
    pub expected_digest: Sha256Digest,
    /// Supplies the verified desired planning-snapshot commitment.
    pub desired_planning: Sha256Digest,
    /// Supplies the verified prior planning-snapshot commitment.
    pub current_planning: Sha256Digest,
    /// Supplies the currently active runtime policy revision.
    pub authorization_policy_revision: RevisionId,
    /// Supplies the checked desired binding plan.
    pub desired: &'a CheckedBindingPlan,
    /// Supplies the checked prior binding plan.
    pub current: &'a CheckedBindingPlan,
}

/// Retains checked current-policy authority and its transition binding projection.
#[derive(Clone, Debug)]
pub struct CheckedTransitionAuthority {
    digest: Sha256Digest,
    document: TransitionAuthorizationDocument,
    binding_plan: CheckedBindingPlan,
}

impl CheckedTransitionAuthority {
    /// Returns the authenticated authorization document commitment.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Returns the checked portable authorization document.
    #[must_use]
    pub const fn document(&self) -> &TransitionAuthorizationDocument {
        &self.document
    }

    /// Returns the desired and teardown bindings in canonical transition order.
    #[must_use]
    pub fn bindings(&self) -> &[Binding] {
        self.binding_plan.bindings()
    }

    /// Returns the complete exact desired and prior package catalog.
    #[must_use]
    pub fn packages(&self) -> &[PackageDocument] {
        self.binding_plan.packages()
    }

    /// Returns the sealed binding projection used only for transition effects.
    #[must_use]
    pub const fn binding_plan(&self) -> &CheckedBindingPlan {
        &self.binding_plan
    }
}

/// Reports why current-policy transition authority cannot be trusted.
#[derive(Debug, Error)]
pub enum TransitionAuthorityError {
    /// Canonical document validation or hashing failed.
    #[error("transition authorization encoding failed: {0}")]
    Encoding(String),
    /// The document or one of its required semantics is unsupported.
    #[error("invalid transition authorization document: {0}")]
    InvalidDocument(String),
    /// An independently supplied commitment differs from the document.
    #[error("transition authorization commitment mismatch: {0}")]
    Commitment(&'static str),
    /// A teardown entry does not select an exact prior binding.
    #[error("invalid teardown binding {binding:?}: {reason}")]
    Binding {
        /// Identifies the transition-local binding.
        binding: BindingId,
        /// Describes the rejected invariant.
        reason: String,
    },
}

impl ValidationContext {
    /// Checks fresh teardown grants against exact desired and prior plan identity.
    ///
    /// The prior plan supplies selection and state evidence only. Every method
    /// used during teardown must appear in the newly authenticated document.
    ///
    /// # Errors
    ///
    /// Returns an error for a mismatched commitment or policy revision, a
    /// superseded prior selection, colliding identifiers, malformed grants,
    /// or implicit persistent-resource deletion.
    pub fn validate_transition_authority(
        &self,
        document: TransitionAuthorizationDocument,
        inputs: TransitionAuthorityInputs<'_>,
    ) -> Result<CheckedTransitionAuthority, TransitionAuthorityError> {
        validate_document(self, &document, &inputs)?;
        let digest = document
            .content_digest()
            .map_err(|error| TransitionAuthorityError::Encoding(error.to_string()))?;
        if digest != inputs.expected_digest {
            return Err(TransitionAuthorityError::Commitment(
                "document differs from its independently authenticated digest",
            ));
        }

        let binding_plan = transition_binding_plan(self, &document, &inputs)?;
        Ok(CheckedTransitionAuthority {
            digest,
            document,
            binding_plan,
        })
    }
}

fn validate_document(
    context: &ValidationContext,
    document: &TransitionAuthorizationDocument,
    inputs: &TransitionAuthorityInputs<'_>,
) -> Result<(), TransitionAuthorityError> {
    document
        .validate_structure(&aos_ability_model::ABILITY_LIMITS_V1)
        .map_err(|error| TransitionAuthorityError::InvalidDocument(error.to_string()))?;
    encode_canonical(document)
        .map_err(|error| TransitionAuthorityError::Encoding(error.to_string()))?;
    if document
        .required_features
        .iter()
        .any(|feature| !context.supported_features().contains(feature))
    {
        return Err(TransitionAuthorityError::InvalidDocument(
            "authorization requires an unsupported semantic feature".to_string(),
        ));
    }
    if document.desired_planning != inputs.desired_planning
        || document.current_planning != inputs.current_planning
    {
        return Err(TransitionAuthorityError::Commitment(
            "planning snapshot identity differs from the checked inputs",
        ));
    }
    if document.desired_policy_revision != inputs.desired.document().policy_revision
        || document.prior_policy_revision != inputs.current.document().policy_revision
        || document.authorization_policy_revision != inputs.authorization_policy_revision
        || document.authorization_policy_revision != document.desired_policy_revision
    {
        return Err(TransitionAuthorityError::Commitment(
            "policy revision differs from the checked inputs",
        ));
    }
    if inputs.desired.environment().environment != inputs.current.environment().environment
        || inputs.desired.environment().platform != inputs.current.environment().platform
    {
        return Err(TransitionAuthorityError::Commitment(
            "desired and prior plans target different environment or platform identities",
        ));
    }
    if document.teardown_bindings.len()
        > aos_ability_model::ABILITY_LIMITS_V1.max_graph_nodes as usize
        || document.teardown_providers.len()
            > aos_ability_model::ABILITY_LIMITS_V1.max_graph_nodes as usize
        || document.persistent_deletions.len()
            > aos_ability_model::ABILITY_LIMITS_V1.max_graph_nodes as usize
    {
        return Err(TransitionAuthorityError::InvalidDocument(
            "authorization exceeds the transition binding limit".to_string(),
        ));
    }
    if document.teardown_bindings.windows(2).any(|pair| {
        (
            &pair[0].source_binding,
            &pair[0].request.id,
            &pair[0].binding.id,
        ) >= (
            &pair[1].source_binding,
            &pair[1].request.id,
            &pair[1].binding.id,
        )
    }) {
        return Err(TransitionAuthorityError::InvalidDocument(
            "teardown bindings are not in strict canonical order".to_string(),
        ));
    }
    if document.teardown_providers.windows(2).any(|pair| {
        (&pair[0].provider, pair[0].implementation.descriptor)
            >= (&pair[1].provider, pair[1].implementation.descriptor)
    }) {
        return Err(TransitionAuthorityError::InvalidDocument(
            "teardown providers are not in strict canonical order".to_string(),
        ));
    }
    if document.persistent_deletions.windows(2).any(|pair| {
        (&pair[0].resource, &pair[0].source_binding, &pair[0].binding)
            >= (&pair[1].resource, &pair[1].source_binding, &pair[1].binding)
    }) {
        return Err(TransitionAuthorityError::InvalidDocument(
            "persistent deletions are not in strict canonical resource order".to_string(),
        ));
    }
    let adoption_feature = aos_ability_model::RequiredFeature::new(PROVIDER_STATE_ADOPTION_FEATURE)
        .map_err(|error| TransitionAuthorityError::InvalidDocument(error.to_string()))?;
    let declares_adoption = document.required_features.contains(&adoption_feature);
    if declares_adoption != !document.provider_adoptions.is_empty() {
        return Err(TransitionAuthorityError::InvalidDocument(
            "provider adoption entries and their required semantic feature must appear together"
                .to_string(),
        ));
    }
    if document.provider_adoptions.len()
        > aos_ability_model::ABILITY_LIMITS_V1.max_graph_nodes as usize
    {
        return Err(TransitionAuthorityError::InvalidDocument(
            "authorization exceeds the provider adoption limit".to_string(),
        ));
    }
    if document
        .provider_adoptions
        .windows(2)
        .any(|pair| pair[0].resource >= pair[1].resource)
    {
        return Err(TransitionAuthorityError::InvalidDocument(
            "provider adoptions are not in strict canonical resource order".to_string(),
        ));
    }
    for provider in &document.teardown_providers {
        validate_teardown_provider(context, document, inputs, provider)?;
    }
    for deletion in &document.persistent_deletions {
        validate_persistent_deletion(context, document, inputs, deletion)?;
    }
    for adoption in &document.provider_adoptions {
        validate_provider_adoption(context, inputs, adoption)?;
    }
    Ok(())
}

fn validate_persistent_deletion(
    context: &ValidationContext,
    document: &TransitionAuthorizationDocument,
    inputs: &TransitionAuthorityInputs<'_>,
    authorization: &aos_ability_model::PersistentResourceDeletionAuthorization,
) -> Result<(), TransitionAuthorityError> {
    let Some(teardown) = document.teardown_bindings.iter().find(|entry| {
        entry.source_binding == authorization.source_binding
            && entry.binding.id == authorization.binding
    }) else {
        return Err(TransitionAuthorityError::InvalidDocument(
            "persistent deletion does not name one exact teardown binding".to_string(),
        ));
    };
    let Some(source) = inputs.current.binding(&authorization.source_binding) else {
        return Err(TransitionAuthorityError::InvalidDocument(
            "persistent deletion source binding is absent from the prior plan".to_string(),
        ));
    };
    let retained_resource = inputs
        .current
        .desired_state()
        .resources
        .iter()
        .find(|revision| revision.resource == authorization.resource);
    if retained_resource.is_none_or(|revision| revision.lifetime != ResourceLifetime::Persistent)
        || source.lifetime != ResourceLifetime::Persistent
        || teardown.binding.lifetime != ResourceLifetime::Persistent
        || !source_resource(source, &authorization.resource)
    {
        return Err(TransitionAuthorityError::InvalidDocument(
            "persistent deletion is not confined to one retained persistent resource".to_string(),
        ));
    }
    let Some(interface) = context.interface(&teardown.binding.interface) else {
        return Err(binding_error(
            &teardown.binding,
            "persistent deletion interface is absent from the catalog",
        ));
    };
    if interface
        .interface
        .lifecycle
        .persistent_delete_method
        .as_ref()
        != Some(&authorization.method)
        || !teardown
            .binding
            .caller_grant
            .methods
            .contains(&authorization.method)
        || teardown
            .binding
            .provider_grant
            .methods
            .contains(&authorization.method)
    {
        return Err(binding_error(
            &teardown.binding,
            "persistent deletion does not use the interface's exact caller-authorized delete method",
        ));
    }
    let matching_permissions = teardown
        .binding
        .caller_grant
        .resources
        .iter()
        .filter(|permission| permission.resource == authorization.resource)
        .collect::<Vec<_>>();
    if matching_permissions.len() != 1
        || matching_permissions[0].access != AccessMode::ExclusiveWrite
        || matching_permissions[0].operations.as_slice()
            != std::slice::from_ref(&authorization.method)
    {
        return Err(binding_error(
            &teardown.binding,
            "persistent deletion requires one exact exclusive caller resource grant",
        ));
    }
    Ok(())
}

fn validate_provider_adoption(
    context: &ValidationContext,
    inputs: &TransitionAuthorityInputs<'_>,
    authorization: &aos_ability_model::ProviderAdoptionAuthorization,
) -> Result<(), TransitionAuthorityError> {
    if authorization.resource.provider != authorization.source.provider
        || authorization.source.provider != authorization.candidate.provider
        || authorization.source.interface != authorization.candidate.interface
    {
        return Err(TransitionAuthorityError::InvalidDocument(
            "provider adoption does not preserve one resource owner and public interface"
                .to_string(),
        ));
    }
    if authorization.source.state_format.descriptor
        != authorization.candidate.state_format.descriptor
    {
        return Err(TransitionAuthorityError::InvalidDocument(
            "provider adoption state-format descriptors are incompatible".to_string(),
        ));
    }
    if same_durable_adoption_authority(&authorization.source, &authorization.candidate) {
        return Err(TransitionAuthorityError::InvalidDocument(
            "provider adoption does not change durable owner or handler authority".to_string(),
        ));
    }

    validate_adoption_endpoint(
        context,
        inputs.current,
        &authorization.resource,
        &authorization.resource_interface,
        &authorization.source,
        "source",
    )?;
    validate_adoption_endpoint(
        context,
        inputs.desired,
        &authorization.resource,
        &authorization.resource_interface,
        &authorization.candidate,
        "candidate",
    )?;
    Ok(())
}

fn same_durable_adoption_authority(
    source: &aos_ability_model::ProviderAdoptionEndpoint,
    candidate: &aos_ability_model::ProviderAdoptionEndpoint,
) -> bool {
    source.provider == candidate.provider
        && source.package == candidate.package
        && source.interface == candidate.interface
        && source.implementation == candidate.implementation
        && source.state_format == candidate.state_format
        && source.handler_package == candidate.handler_package
        && source.handler_provider == candidate.handler_provider
        && source.handler_interface == candidate.handler_interface
        && source.handler_implementation == candidate.handler_implementation
}

fn validate_adoption_endpoint(
    context: &ValidationContext,
    plan: &CheckedBindingPlan,
    resource: &aos_ability_model::ResourceId,
    resource_interface: &aos_ability_model::InterfaceKey,
    endpoint: &ProviderAdoptionEndpoint,
    label: &str,
) -> Result<(), TransitionAuthorityError> {
    if !plan
        .document()
        .resources
        .iter()
        .any(|revision| revision.resource == *resource)
    {
        return Err(TransitionAuthorityError::InvalidDocument(format!(
            "provider adoption {label} plan does not retain the exact resource"
        )));
    }
    let binding = plan.binding(&endpoint.handler_binding).ok_or_else(|| {
        TransitionAuthorityError::InvalidDocument(format!(
            "provider adoption {label} handler binding is absent"
        ))
    })?;
    let request = plan
        .document()
        .requests
        .iter()
        .find(|request| request.id == binding.request)
        .ok_or_else(|| {
            TransitionAuthorityError::InvalidDocument(format!(
                "provider adoption {label} handler request is absent"
            ))
        })?;
    if endpoint.handler_interface != *resource_interface
        || binding.provider != endpoint.handler_provider
        || binding.interface != endpoint.handler_interface
        || binding.implementation != endpoint.handler_implementation
        || binding.provider_package != Some(endpoint.handler_package)
        || request.id.consumer != endpoint.provider
        || !scope_belongs_to_owner(&request.id.scope, &endpoint.provider)
        || request.lifetime != ResourceLifetime::Persistent
        || binding.lifetime != ResourceLifetime::Persistent
        || !request.methods.contains(&endpoint.handler_method)
        || !binding
            .caller_grant
            .methods
            .contains(&endpoint.handler_method)
        || context
            .interface(&endpoint.handler_interface)
            .and_then(|interface| interface.interface.methods.get(&endpoint.handler_method))
            .is_none_or(|method| method.target_resource != resource_interface.name)
        || !binding.caller_grant.resources.iter().any(|permission| {
            permission.resource == *resource
                && permission.access.is_write()
                && permission.operations.contains(&endpoint.handler_method)
        })
    {
        return Err(TransitionAuthorityError::InvalidDocument(format!(
            "provider adoption {label} handler differs from its exact owner-scoped checked binding and write grant"
        )));
    }
    if !plan.environment().providers.iter().any(|provider| {
        provider.provider == endpoint.handler_provider
            && provider.interface == endpoint.handler_interface
            && provider.implementation == endpoint.handler_implementation
            && provider.state == ProviderState::Available
            && provider.incarnation.as_ref() == Some(&endpoint.handler_incarnation)
    }) {
        return Err(TransitionAuthorityError::InvalidDocument(format!(
            "provider adoption {label} incarnation is not the exact checked available assignment"
        )));
    }

    let package = exact_package(plan.packages(), endpoint.package).ok_or_else(|| {
        TransitionAuthorityError::InvalidDocument(format!(
            "provider adoption {label} owner package is absent or ambiguous"
        ))
    })?;
    if !owner_implementation_is_selected(plan, endpoint) {
        return Err(TransitionAuthorityError::InvalidDocument(format!(
            "provider adoption {label} owner is not an exact selected package implementation"
        )));
    }
    let implementation = exact_provider_implementation(package, &endpoint.implementation)
        .filter(|implementation| implementation.interface == endpoint.interface)
        .ok_or_else(|| {
            TransitionAuthorityError::InvalidDocument(format!(
                "provider adoption {label} owner implementation is not authenticated by its package"
            ))
        })?;
    if implementation.state_format.as_ref() != Some(&endpoint.state_format)
        || endpoint.state_format.artifact != endpoint.implementation.artifact
        || implementation.provider_module.is_none()
        || context.interface(&endpoint.interface).is_none()
        || !implementation
            .owns_resource_kinds
            .contains(&resource_interface.name)
        || context.interface(resource_interface).is_none()
    {
        return Err(TransitionAuthorityError::InvalidDocument(format!(
            "provider adoption {label} owner lacks its exact interface or authenticated state format"
        )));
    }

    let handler_package =
        exact_package(plan.packages(), endpoint.handler_package).ok_or_else(|| {
            TransitionAuthorityError::InvalidDocument(format!(
                "provider adoption {label} handler package is absent or ambiguous"
            ))
        })?;
    let handler = exact_provider_implementation(handler_package, &endpoint.handler_implementation)
        .filter(|implementation| implementation.interface == endpoint.handler_interface)
        .ok_or_else(|| {
            TransitionAuthorityError::InvalidDocument(format!(
                "provider adoption {label} terminal implementation is not authenticated by its package"
            ))
        })?;
    let exact_handler = handler.handler.as_ref().is_some_and(|handler| {
        endpoint.handler_implementation.handler.as_ref() == Some(handler)
            && handler_package
                .implementation
                .handlers
                .get(handler)
                .is_some_and(|descriptor| {
                    descriptor.artifact == endpoint.handler_implementation.artifact
                })
    });
    let exact_resource_method = context
        .interface(&endpoint.handler_interface)
        .and_then(|document| document.interface.methods.get(&endpoint.handler_method))
        .is_some_and(|method| method.target_resource == resource_interface.name);
    if !exact_handler || !exact_resource_method {
        return Err(TransitionAuthorityError::InvalidDocument(format!(
            "provider adoption {label} handler is not an authenticated terminal method for the retained resource kind"
        )));
    }
    Ok(())
}

fn owner_implementation_is_selected(
    plan: &CheckedBindingPlan,
    endpoint: &ProviderAdoptionEndpoint,
) -> bool {
    plan.bindings().iter().any(|binding| {
        binding.provider == endpoint.provider
            && binding.provider_package == Some(endpoint.package)
            && binding.interface == endpoint.interface
            && binding.implementation == endpoint.implementation
            && binding.lifetime == ResourceLifetime::Persistent
            && plan.document().requests.iter().any(|request| {
                request.id == binding.request && request.lifetime == ResourceLifetime::Persistent
            })
    })
}

fn scope_belongs_to_owner(
    scope: &aos_ability_model::ScopePath,
    owner: &aos_ability_model::InstanceId,
) -> bool {
    scope.as_slice().first() == Some(&owner.key)
}

fn exact_package(packages: &[PackageDocument], digest: Sha256Digest) -> Option<&PackageDocument> {
    let mut matches = packages.iter().filter(|package| {
        package
            .content_digest()
            .is_ok_and(|candidate| candidate == digest)
    });
    let package = matches.next()?;
    matches.next().is_none().then_some(package)
}

fn exact_provider_implementation<'a>(
    package: &'a PackageDocument,
    reference: &aos_ability_model::ProviderImplementationReference,
) -> Option<&'a ProviderImplementation> {
    let mut matches = package
        .implementation
        .providers
        .iter()
        .filter(|implementation| {
            implementation.artifact == reference.artifact
                && implementation
                    .descriptor_digest()
                    .is_ok_and(|descriptor| descriptor == reference.descriptor)
                && package.exports.iter().any(|export| {
                    export.interface == implementation.interface
                        && export.implementation == reference.descriptor
                })
        });
    let implementation = matches.next()?;
    matches.next().is_none().then_some(implementation)
}

fn transition_binding_plan(
    context: &ValidationContext,
    document: &TransitionAuthorizationDocument,
    inputs: &TransitionAuthorityInputs<'_>,
) -> Result<CheckedBindingPlan, TransitionAuthorityError> {
    let mut binding_document = inputs.desired.document().clone();
    let mut binding_ids: BTreeSet<_> = binding_document
        .bindings
        .iter()
        .map(|binding| binding.id.clone())
        .collect();
    binding_ids.extend(
        inputs
            .current
            .bindings()
            .iter()
            .map(|binding| binding.id.clone()),
    );
    let mut source_ids = BTreeSet::new();
    let current_requests: BTreeMap<_, _> = inputs
        .current
        .document()
        .requests
        .iter()
        .map(|request| (&request.id, request))
        .collect();
    let mut request_ids: BTreeSet<_> = binding_document
        .requests
        .iter()
        .chain(inputs.current.document().requests.iter())
        .map(|request| request.id.clone())
        .collect();

    for authorization in &document.teardown_bindings {
        let binding = &authorization.binding;
        let Some(source) = inputs.current.binding(&authorization.source_binding) else {
            return Err(binding_error(
                binding,
                "source binding is absent from the prior plan",
            ));
        };
        if !source_ids.insert(authorization.source_binding.clone()) {
            return Err(binding_error(
                binding,
                "one prior source binding is reauthorized more than once",
            ));
        }
        let source_request = current_requests.get(&source.request).ok_or_else(|| {
            binding_error(binding, "source request is absent from the prior plan")
        })?;
        validate_teardown_binding(
            context,
            document,
            inputs.current,
            source,
            source_request,
            authorization,
        )?;
        if !binding_ids.insert(binding.id.clone()) {
            return Err(binding_error(
                binding,
                "transition-local identity collides with a desired, prior, or teardown binding",
            ));
        }
        if !request_ids.insert(authorization.request.id.clone()) {
            return Err(binding_error(
                binding,
                "transition-local request identity collides with a desired or prior request",
            ));
        }
        binding_document.bindings.push(binding.clone());
        binding_document
            .requests
            .push(authorization.request.clone());
    }

    binding_document
        .bindings
        .sort_by(|left, right| left.id.cmp(&right.id));
    binding_document
        .requests
        .sort_by(|left, right| left.id.cmp(&right.id));
    let desired_resources: BTreeSet<_> = binding_document
        .resources
        .iter()
        .map(|revision| revision.resource.clone())
        .collect();
    binding_document.resources.extend(
        inputs
            .current
            .document()
            .resources
            .iter()
            .filter(|prior| !desired_resources.contains(&prior.resource))
            .cloned(),
    );
    binding_document
        .resources
        .sort_by(|left, right| left.resource.cmp(&right.resource));

    let packages = union_packages(inputs.desired.packages(), inputs.current.packages())?;
    validate_projection_bounds(&binding_document, &packages)?;
    let id = binding_document
        .content_digest()
        .map(PlanId)
        .map_err(|error| TransitionAuthorityError::Encoding(error.to_string()))?;
    let binding_indices = binding_document
        .bindings
        .iter()
        .enumerate()
        .map(|(index, binding)| (binding.id.clone(), index))
        .collect();
    let teardown_ids: BTreeSet<_> = document
        .teardown_bindings
        .iter()
        .map(|entry| entry.binding.id.clone())
        .collect();
    let mut binding_authority: BTreeMap<_, _> = inputs
        .desired
        .bindings()
        .iter()
        .map(|binding| (binding.id.clone(), BindingAuthorityKind::Desired))
        .collect();
    for authorization in &document.teardown_bindings {
        let source = inputs
            .current
            .binding(&authorization.source_binding)
            .ok_or_else(|| binding_error(&authorization.binding, "source binding disappeared"))?;
        binding_authority.insert(
            authorization.binding.id.clone(),
            BindingAuthorityKind::Teardown {
                source_binding: authorization.source_binding.clone(),
                source_request: source.request.clone(),
            },
        );
    }
    let mut provider_states = BTreeMap::new();
    let mut planned_providers = inputs.desired.planned_providers().clone();
    for binding in &binding_document.bindings {
        let state = if teardown_ids.contains(&binding.id) {
            fresh_teardown_provider_state(inputs, binding)?
        } else {
            inputs.desired.provider_state(&binding.id).ok_or_else(|| {
                binding_error(binding, "desired binding lost its checked provider state")
            })?
        };
        if state == BindingProviderState::Planned {
            planned_providers.insert(binding.provider.clone());
        }
        provider_states.insert(binding.id.clone(), state);
    }

    let executable = inputs.desired.is_executable() && planned_providers.is_empty();
    Ok(CheckedBindingPlan {
        id,
        document: binding_document,
        inputs: BindingValidationInputs {
            environment: inputs.desired.environment().clone(),
            desired_state: inputs.desired.desired_state().clone(),
            packages,
        },
        binding_indices,
        binding_authority,
        provider_states,
        planned_providers,
        executable,
    })
}

fn validate_teardown_provider(
    context: &ValidationContext,
    document: &TransitionAuthorizationDocument,
    inputs: &TransitionAuthorityInputs<'_>,
    authorization: &aos_ability_model::TeardownProviderAuthorization,
) -> Result<(), TransitionAuthorityError> {
    if authorization.policy_revision != document.authorization_policy_revision {
        return Err(TransitionAuthorityError::InvalidDocument(
            "teardown provider does not use the fresh policy revision".to_string(),
        ));
    }
    let retained_instance = inputs
        .current
        .desired_state()
        .instances
        .iter()
        .any(|instance| {
            instance.enabled
                && instance.instance == authorization.provider
                && instance.package == authorization.package
        });
    let retained_package = inputs.current.packages().iter().find(|package| {
        package
            .content_digest()
            .is_ok_and(|digest| digest == authorization.package)
    });
    let Some(implementation) = retained_package.and_then(|package| {
        package
            .implementation
            .providers
            .iter()
            .find(|implementation| {
                implementation.artifact == authorization.implementation.artifact
                    && implementation.handler == authorization.implementation.handler
                    && implementation
                        .descriptor_digest()
                        .is_ok_and(|digest| digest == authorization.implementation.descriptor)
            })
    }) else {
        return Err(TransitionAuthorityError::InvalidDocument(
            "teardown provider package does not retain its exact implementation".to_string(),
        ));
    };
    if !retained_instance {
        return Err(TransitionAuthorityError::InvalidDocument(
            "teardown provider is not an exact prior enabled package instance".to_string(),
        ));
    }
    let valid_constructor = implementation.provider_module.is_some()
        && retained_package.is_some_and(|package| {
            package.exports.iter().any(|export| {
                export.interface == implementation.interface
                    && export.implementation == authorization.implementation.descriptor
            })
        });
    if !valid_constructor {
        return Err(TransitionAuthorityError::InvalidDocument(
            "teardown provider is not an exact retained operator-enabled constructor".to_string(),
        ));
    }
    if context.interface(&implementation.interface).is_none() {
        return Err(TransitionAuthorityError::InvalidDocument(
            "teardown provider interface is absent from the validated catalog".to_string(),
        ));
    }
    Ok(())
}

fn validate_projection_bounds(
    document: &aos_ability_model::BindingPlanDocument,
    packages: &[PackageDocument],
) -> Result<(), TransitionAuthorityError> {
    let limits = aos_ability_model::ABILITY_LIMITS_V1;
    if document.bindings.len() > limits.max_graph_nodes as usize
        || document.requests.len() > limits.max_graph_nodes as usize
        || document.resources.len() > limits.max_graph_nodes as usize
        || packages.len() > limits.max_graph_nodes as usize
    {
        return Err(TransitionAuthorityError::InvalidDocument(
            "combined transition projection exceeds a version-1 entry limit".to_string(),
        ));
    }
    encode_canonical(document)
        .map_err(|error| TransitionAuthorityError::InvalidDocument(error.to_string()))?;
    let mut package_bytes = 0_u64;
    for package in packages {
        let bytes = encode_canonical(package)
            .map_err(|error| TransitionAuthorityError::InvalidDocument(error.to_string()))?;
        package_bytes = package_bytes.saturating_add(bytes.len() as u64);
        if package_bytes > limits.max_document_bytes {
            return Err(TransitionAuthorityError::InvalidDocument(
                "combined transition package catalog exceeds the version-1 byte limit".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_teardown_binding(
    context: &ValidationContext,
    document: &TransitionAuthorizationDocument,
    _current: &CheckedBindingPlan,
    source: &Binding,
    source_request: &aos_ability_model::BindingRequest,
    authorization: &aos_ability_model::TeardownBindingAuthorization,
) -> Result<(), TransitionAuthorityError> {
    let binding = &authorization.binding;
    let request = &authorization.request;
    if binding.request != request.id
        || request.id.consumer != source_request.id.consumer
        || request.id.scope != source_request.id.scope
        || request.accepted_interfaces != source_request.accepted_interfaces
        || request.methods != source_request.methods
        || request.guarantees != source_request.guarantees
        || request.lifetime != source_request.lifetime
    {
        return Err(binding_error(
            binding,
            "transition request does not exactly remap prior request provenance",
        ));
    }
    if binding.interface != source.interface
        || binding.provider != source.provider
        || binding.provider_package != source.provider_package
        || binding.implementation != source.implementation
        || binding.source != source.source
        || binding.guarantees != source.guarantees
        || binding.lifetime != source.lifetime
    {
        return Err(binding_error(
            binding,
            "selection provenance differs from the exact prior binding",
        ));
    }
    if binding.policy_revision != document.authorization_policy_revision {
        return Err(binding_error(
            binding,
            "binding does not use the fresh authorization policy revision",
        ));
    }
    if binding.caller_grant.principal != source_request.id.consumer
        || binding.provider_grant.principal != binding.provider
    {
        return Err(binding_error(
            binding,
            "fresh grant principals do not match the selection",
        ));
    }
    if !binding.caller_grant.contributions.is_empty()
        || !binding.provider_grant.contributions.is_empty()
    {
        return Err(binding_error(
            binding,
            "teardown authority cannot adopt or populate aggregate ownership",
        ));
    }
    if !binding.mediation_allowed
        && (!binding.provider_grant.methods.is_empty()
            || !binding.provider_grant.resources.is_empty())
    {
        return Err(binding_error(
            binding,
            "provider authority requires explicit current-policy mediation",
        ));
    }
    let Some(interface) = context.interface(&binding.interface) else {
        return Err(binding_error(
            binding,
            "exact interface is absent from the catalog",
        ));
    };
    let persistent_delete = interface
        .interface
        .lifecycle
        .persistent_delete_method
        .as_ref();
    let explicitly_authorized_delete = |method: &aos_ability_model::LocalKey| {
        document.persistent_deletions.iter().any(|deletion| {
            deletion.source_binding == authorization.source_binding
                && deletion.binding == binding.id
                && deletion.method == *method
        })
    };
    for (grant, caller_grant) in [
        (&binding.caller_grant, true),
        (&binding.provider_grant, false),
    ] {
        if grant.methods.windows(2).any(|pair| pair[0] >= pair[1])
            || grant
                .methods
                .iter()
                .any(|method| !interface.interface.methods.contains_key(method))
        {
            return Err(binding_error(
                binding,
                "fresh grant methods are not exact and canonical",
            ));
        }
        if let Some(method) = persistent_delete {
            let grants_delete = grant.methods.contains(method);
            if grants_delete && (!caller_grant || !explicitly_authorized_delete(method)) {
                return Err(binding_error(
                    binding,
                    "persistent deletion requires a separately typed caller authorization",
                ));
            }
        }
        if grant
            .resources
            .windows(2)
            .any(|pair| pair[0].resource >= pair[1].resource)
            || grant.resources.iter().any(|permission| {
                let mediated_owner_write = caller_grant
                    && permission.resource.provider == request.id.consumer
                    && permission.access.is_write()
                    && request.lifetime == binding.lifetime
                    && !permission.operations.is_empty()
                    && permission.operations.iter().all(|operation| {
                        binding.caller_grant.methods.contains(operation)
                            && interface.interface.methods.get(operation).is_some()
                    });
                (permission.resource.provider != binding.provider && !mediated_owner_write)
                    || permission
                        .operations
                        .windows(2)
                        .any(|pair| pair[0] >= pair[1])
                    || !source_resource(source, &permission.resource)
            })
        {
            return Err(binding_error(
                binding,
                "fresh resource grants exceed checked resource scope",
            ));
        }
    }
    Ok(())
}

fn source_resource(source: &Binding, resource: &aos_ability_model::ResourceId) -> bool {
    source
        .caller_grant
        .resources
        .iter()
        .chain(source.provider_grant.resources.iter())
        .any(|permission| &permission.resource == resource)
}

fn fresh_teardown_provider_state(
    inputs: &TransitionAuthorityInputs<'_>,
    binding: &Binding,
) -> Result<BindingProviderState, TransitionAuthorityError> {
    if binding.implementation.handler.is_none() {
        return Ok(BindingProviderState::PureComposition);
    }
    let inventory = inputs
        .desired
        .environment()
        .providers
        .iter()
        .find(|provider| {
            provider.provider == binding.provider
                && provider.interface == binding.interface
                && provider.implementation == binding.implementation
        })
        .ok_or_else(|| {
            binding_error(
                binding,
                "teardown terminal lacks exact fresh provider inventory",
            )
        })?;
    match inventory.state {
        ProviderState::Available if inventory.incarnation.is_some() => {
            Ok(BindingProviderState::Available)
        }
        ProviderState::Planned if inventory.incarnation.is_none() => {
            Ok(BindingProviderState::Planned)
        }
        ProviderState::Declared
        | ProviderState::Unavailable
        | ProviderState::Stale
        | ProviderState::Available
        | ProviderState::Planned => Err(binding_error(
            binding,
            "teardown terminal is not freshly available or consistently planned",
        )),
    }
}

fn union_packages(
    desired: &[PackageDocument],
    current: &[PackageDocument],
) -> Result<Vec<PackageDocument>, TransitionAuthorityError> {
    let mut packages = BTreeMap::new();
    for package in desired.iter().chain(current) {
        let digest = package
            .content_digest()
            .map_err(|error| TransitionAuthorityError::Encoding(error.to_string()))?;
        if let Some(existing) = packages.insert(digest, package.clone())
            && existing != *package
        {
            return Err(TransitionAuthorityError::InvalidDocument(
                "same package identity has conflicting content".to_string(),
            ));
        }
    }
    Ok(packages.into_values().collect())
}

fn binding_error(binding: &Binding, reason: impl Into<String>) -> TransitionAuthorityError {
    TransitionAuthorityError::Binding {
        binding: binding.id.clone(),
        reason: reason.into(),
    }
}

#[cfg(test)]
#[path = "transition_authority_tests.rs"]
mod tests;
