//! Validation and sealing of fresh authority used while retiring prior state.

use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::document::ProviderState;
use aos_ability_model::{
    Binding, BindingId, ImplementationKind, PROVIDER_STATE_ADOPTION_V1, PackageDocument, PlanId,
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
    let adoption_feature = aos_ability_model::RequiredFeature::new(PROVIDER_STATE_ADOPTION_V1)
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
    for adoption in &document.provider_adoptions {
        validate_provider_adoption(context, inputs, adoption)?;
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
        || !matches!(
            implementation.implementation,
            ImplementationKind::PureComposition { .. }
        )
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
    let exact_handler = match &handler.implementation {
        ImplementationKind::TerminalHandler { handler } => {
            endpoint.handler_implementation.handler.as_ref() == Some(handler)
                && handler_package
                    .implementation
                    .handlers
                    .get(handler)
                    .is_some_and(|descriptor| {
                        descriptor.artifact == endpoint.handler_implementation.artifact
                    })
        }
        ImplementationKind::PureComposition { .. } => false,
    };
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
    let valid_constructor = match &implementation.implementation {
        ImplementationKind::PureComposition {
            compose_entry,
            transition_entry,
        } => {
            authorization.implementation.handler.is_none()
                && retained_package.is_some_and(|package| {
                    package.module_entry_points.get(compose_entry)
                        == Some(&authorization.implementation.artifact)
                        && package.module_entry_points.get(transition_entry)
                            == Some(&authorization.implementation.artifact)
                        && package.exports.iter().any(|export| {
                            export.interface == implementation.interface
                                && export.implementation == authorization.implementation.descriptor
                                && export.aggregation.is_some()
                        })
                })
        }
        ImplementationKind::TerminalHandler { .. } => false,
    };
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
        if persistent_delete.is_some_and(|method| grant.methods.contains(method)) {
            return Err(binding_error(
                binding,
                "persistent deletion requires a separately typed authorization",
            ));
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
    if binding.lifetime == ResourceLifetime::Persistent
        && persistent_delete.is_some_and(|method| {
            binding.caller_grant.methods.contains(method)
                || binding.provider_grant.methods.contains(method)
        })
    {
        return Err(binding_error(
            binding,
            "persistent resource deletion is not implicit teardown",
        ));
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
mod tests {
    use aos_ability_model::document::{DesiredInstance, PackageSubject};
    use aos_ability_model::identity::compare_request_ids;
    use aos_ability_model::{
        AbilityActivationMode, AccessMode, AggregateId, BindingRequest, ContributionPermission,
        ExportDeclaration, HandlerDescriptor, InterfaceName, LocalKey, PackageImplementation,
        ProviderAdoptionAuthorization, ProviderImplementation, ProviderImplementationReference,
        ProviderStateFormat, RequiredFeature, ResourcePermission, ScopePath,
        TeardownBindingAuthorization, ValueSchema,
    };

    use super::*;

    #[derive(Clone)]
    struct AuthorityFixture {
        context: ValidationContext,
        desired: CheckedBindingPlan,
        current: CheckedBindingPlan,
        document: TransitionAuthorizationDocument,
    }

    impl AuthorityFixture {
        fn validate(&self) -> Result<CheckedTransitionAuthority, TransitionAuthorityError> {
            let expected_digest = self
                .document
                .content_digest()
                .expect("test authorization must digest");
            self.context.validate_transition_authority(
                self.document.clone(),
                TransitionAuthorityInputs {
                    expected_digest,
                    desired_planning: self.document.desired_planning,
                    current_planning: self.document.current_planning,
                    authorization_policy_revision: self.document.authorization_policy_revision,
                    desired: &self.desired,
                    current: &self.current,
                },
            )
        }
    }

    #[test]
    fn current_policy_can_newly_grant_stop_for_exact_prior_selection() {
        let fixture = authority_fixture();
        let checked = fixture
            .validate()
            .expect("fresh Stop authority need not be a subset of historical Start authority");
        let teardown = &checked.document().teardown_bindings[0].binding;

        assert_eq!(teardown.caller_grant.methods, vec![key("stop")]);
        assert_eq!(checked.bindings().last(), Some(teardown));
    }

    #[test]
    fn superseded_policy_revision_fails_closed() {
        let mut fixture = authority_fixture();
        fixture.document.authorization_policy_revision =
            RevisionId(Sha256Digest::of_bytes("superseded transition policy"));

        assert!(matches!(
            fixture.validate(),
            Err(TransitionAuthorityError::Commitment(_))
        ));
    }

    #[test]
    fn changed_prior_selection_fails_closed() {
        let mut fixture = authority_fixture();
        fixture.document.teardown_bindings[0]
            .binding
            .implementation
            .descriptor = Sha256Digest::of_bytes("different implementation");

        assert!(matches!(
            fixture.validate(),
            Err(TransitionAuthorityError::Binding { .. })
        ));
    }

    #[test]
    fn every_prior_binding_identity_is_reserved() {
        let mut fixture = authority_fixture();
        fixture.document.teardown_bindings[0].binding.id = fixture.current.bindings()[0].id.clone();

        assert!(matches!(
            fixture.validate(),
            Err(TransitionAuthorityError::Binding { .. })
        ));
    }

    #[test]
    fn one_prior_source_cannot_be_reauthorized_twice() {
        let mut fixture = authority_fixture();
        let mut duplicate = fixture.document.teardown_bindings[0].clone();
        duplicate.binding.id = BindingId(key("zz-second-teardown"));
        duplicate.request.id.key = key("zz-second-request");
        duplicate.binding.request = duplicate.request.id.clone();
        fixture.document.teardown_bindings.push(duplicate);

        assert!(matches!(
            fixture.validate(),
            Err(TransitionAuthorityError::Binding { .. })
        ));
    }

    #[test]
    fn teardown_cannot_adopt_aggregate_ownership() {
        let mut fixture = authority_fixture();
        let provider = fixture.document.teardown_bindings[0]
            .binding
            .provider
            .clone();
        fixture.document.teardown_bindings[0]
            .binding
            .caller_grant
            .contributions
            .push(ContributionPermission {
                aggregate: AggregateId {
                    provider,
                    group: key("adopted"),
                },
                slot: key("owner"),
            });

        assert!(matches!(
            fixture.validate(),
            Err(TransitionAuthorityError::Binding { .. })
        ));
    }

    #[test]
    fn teardown_resource_must_have_belonged_to_exact_source_grant() {
        let mut fixture = authority_fixture();
        let mut resource = fixture.current.document.resources[0].resource.clone();
        resource.key = key("newly-desired");
        fixture.document.teardown_bindings[0]
            .binding
            .caller_grant
            .resources = vec![ResourcePermission {
            resource,
            access: AccessMode::ExclusiveWrite,
            operations: vec![key("stop")],
        }];

        assert!(matches!(
            fixture.validate(),
            Err(TransitionAuthorityError::Binding { .. })
        ));
    }

    #[test]
    fn stale_teardown_terminal_fails_closed() {
        let mut fixture = authority_fixture();
        fixture.desired.inputs.environment.providers[0].state = ProviderState::Stale;

        assert!(matches!(
            fixture.validate(),
            Err(TransitionAuthorityError::Binding { .. })
        ));
    }

    #[test]
    fn absent_teardown_terminal_fails_closed() {
        let mut fixture = authority_fixture();
        fixture.desired.inputs.environment.providers.clear();

        assert!(matches!(
            fixture.validate(),
            Err(TransitionAuthorityError::Binding { .. })
        ));
    }

    #[test]
    fn planned_teardown_terminal_requires_later_readiness_qualification() {
        let mut fixture = authority_fixture();
        fixture.desired.inputs.environment.providers[0].state = ProviderState::Planned;
        fixture.desired.inputs.environment.providers[0].incarnation = None;
        let checked = fixture
            .validate()
            .expect("consistent planned inventory may be sealed for readiness planning");

        assert!(!checked.binding_plan().is_executable());
        assert!(
            checked
                .binding_plan()
                .planned_providers()
                .contains(&fixture.document.teardown_bindings[0].binding.provider)
        );
    }

    #[test]
    fn different_prior_platform_fails_closed() {
        let mut fixture = authority_fixture();
        fixture.current.inputs.environment.platform.architecture = key("aarch64");

        assert!(matches!(
            fixture.validate(),
            Err(TransitionAuthorityError::Commitment(_))
        ));
    }

    #[test]
    fn persistent_delete_method_requires_separate_authorization_type() {
        let mut fixture = authority_fixture();
        let mut interface = fixture
            .context
            .interfaces()
            .values()
            .next()
            .expect("fixture interface")
            .clone();
        interface.interface.lifecycle.persistent_delete_method = Some(key("stop"));
        let interface_key = interface
            .interface_key()
            .expect("mutated interface must digest");
        fixture.context = ValidationContext::new(BTreeSet::new(), [interface])
            .expect("mutated interface must validate");
        for plan in [&mut fixture.desired, &mut fixture.current] {
            plan.document.bindings[0].interface = interface_key.clone();
            plan.inputs.environment.providers[0].interface = interface_key.clone();
        }
        fixture.document.teardown_bindings[0].binding.interface = interface_key;

        assert!(matches!(
            fixture.validate(),
            Err(TransitionAuthorityError::Binding { .. })
        ));
    }

    #[test]
    fn combined_transition_projection_enforces_the_v1_request_limit() {
        let fixture = authority_fixture();
        let mut projection = fixture.desired.document().clone();
        let request = projection.requests[0].clone();
        projection.requests =
            vec![request; aos_ability_model::ABILITY_LIMITS_V1.max_graph_nodes as usize];
        projection
            .requests
            .push(fixture.document.teardown_bindings[0].request.clone());

        assert!(matches!(
            validate_projection_bounds(&projection, fixture.desired.packages()),
            Err(TransitionAuthorityError::InvalidDocument(_))
        ));
    }

    #[test]
    fn nested_adoption_request_scope_belongs_to_its_owner() {
        let fixture = authority_fixture();
        let owner = fixture.current.document.requests[0].id.consumer.clone();
        let nested_scope = ScopePath::new(vec![owner.key.clone(), key("nested")])
            .expect("nested owner scope must be valid");

        assert!(scope_belongs_to_owner(&nested_scope, &owner));
    }

    #[test]
    fn adoption_request_scope_rejects_a_foreign_first_component() {
        let fixture = authority_fixture();
        let owner = fixture.current.document.requests[0].id.consumer.clone();
        let foreign_scope = ScopePath::new(vec![key("foreign"), owner.key.clone()])
            .expect("foreign test scope must be valid");

        assert!(!scope_belongs_to_owner(&foreign_scope, &owner));
    }

    #[test]
    fn enabled_multi_export_package_cannot_substitute_an_unselected_owner() {
        let (_, plan, endpoint) = multi_export_owner_fixture(false);

        assert!(plan.desired_state().instances.iter().any(|instance| {
            instance.enabled
                && instance.instance == endpoint.provider
                && instance.package == endpoint.package
        }));
        assert!(!owner_implementation_is_selected(&plan, &endpoint));
    }

    #[test]
    fn stateful_owner_fixture_selects_the_exact_export() {
        let (_, plan, endpoint) = multi_export_owner_fixture(true);

        assert!(owner_implementation_is_selected(&plan, &endpoint));
    }

    #[test]
    fn exact_compatible_provider_adoption_is_valid() {
        adoption_authority_fixture()
            .validate()
            .expect("exact compatible adoption authority");
    }

    #[test]
    fn byte_identical_provider_adoption_endpoints_are_rejected() {
        let mut fixture = adoption_authority_fixture();
        fixture.document.provider_adoptions[0].candidate =
            fixture.document.provider_adoptions[0].source.clone();

        assert_invalid_adoption(fixture, "byte-identical endpoints");
    }

    #[test]
    fn binding_and_method_only_provider_adoption_is_rejected() {
        let mut fixture = adoption_authority_fixture();
        let candidate = fixture.document.provider_adoptions[0].candidate.clone();
        let source = &mut fixture.document.provider_adoptions[0].source;
        *source = candidate;
        source.handler_binding = BindingId(key("plan-local-source-binding"));
        source.handler_method = key("plan-local-source-method");

        let error = fixture
            .validate()
            .expect_err("plan-local endpoint fields cannot create durable adoption authority");
        assert!(
            error
                .to_string()
                .contains("does not change durable owner or handler authority"),
            "{error}"
        );
    }

    #[test]
    fn provider_adoption_entries_and_feature_are_coupled() {
        let mut missing_feature = adoption_authority_fixture();
        missing_feature.document.required_features.clear();
        assert_invalid_adoption(missing_feature, "missing adoption feature");

        let mut missing_entry = adoption_authority_fixture();
        missing_entry.document.provider_adoptions.clear();
        assert_invalid_adoption(missing_entry, "adoption feature without entries");
    }

    #[test]
    fn provider_adoptions_require_unique_canonical_resource_order() {
        let mut duplicate = adoption_authority_fixture();
        duplicate
            .document
            .provider_adoptions
            .push(duplicate.document.provider_adoptions[0].clone());
        assert_invalid_adoption(duplicate, "duplicate adoption resource");

        let mut noncanonical = adoption_authority_fixture();
        let mut earlier = noncanonical.document.provider_adoptions[0].clone();
        earlier.resource.key = key("aaa-adoption-resource");
        let mut later = noncanonical.document.provider_adoptions[0].clone();
        later.resource.key = key("zzz-adoption-resource");
        noncanonical.document.provider_adoptions = vec![later, earlier];
        assert_invalid_adoption(noncanonical, "noncanonical adoption resource order");
    }

    #[test]
    fn checked_handler_incarnation_only_adoption_is_not_a_durable_change() {
        let mut fixture = adoption_authority_fixture();
        fixture.current = fixture.desired.clone();
        let candidate = fixture.document.provider_adoptions[0].candidate.clone();
        let source_incarnation = aos_ability_model::IncarnationId::new("prior-checked-handler")
            .expect("valid prior incarnation");
        let source_inventory = fixture
            .current
            .inputs
            .environment
            .providers
            .iter_mut()
            .find(|provider| {
                provider.provider == candidate.handler_provider
                    && provider.interface == candidate.handler_interface
                    && provider.implementation == candidate.handler_implementation
            })
            .expect("source handler inventory");
        source_inventory.incarnation = Some(source_incarnation.clone());

        let source = &mut fixture.document.provider_adoptions[0].source;
        *source = candidate.clone();
        source.handler_incarnation = source_incarnation;
        assert_ne!(*source, candidate);

        assert_invalid_adoption(
            fixture,
            "does not change durable owner or handler authority",
        );
    }

    #[test]
    fn adoption_authority_requires_its_exact_authenticated_digest() {
        let fixture = adoption_authority_fixture();
        let error = fixture
            .context
            .validate_transition_authority(
                fixture.document.clone(),
                TransitionAuthorityInputs {
                    expected_digest: Sha256Digest::of_bytes("wrong adoption authority digest"),
                    desired_planning: fixture.document.desired_planning,
                    current_planning: fixture.document.current_planning,
                    authorization_policy_revision: fixture.document.authorization_policy_revision,
                    desired: &fixture.desired,
                    current: &fixture.current,
                },
            )
            .expect_err("a mismatched authenticated digest must fail");

        assert!(matches!(error, TransitionAuthorityError::Commitment(_)));
    }

    #[test]
    fn stale_source_adoption_endpoint_fields_fail_closed() {
        assert_endpoint_mutations_fail(AdoptionSide::Source);
    }

    #[test]
    fn stale_candidate_adoption_endpoint_fields_fail_closed() {
        assert_endpoint_mutations_fail(AdoptionSide::Candidate);
    }

    #[test]
    fn stale_adoption_resource_and_kind_fail_closed() {
        let mut stale_resource = adoption_authority_fixture();
        stale_resource.document.provider_adoptions[0].resource.key = key("stale-resource");
        assert_invalid_adoption(stale_resource, "stale resource");

        let mut stale_kind = adoption_authority_fixture();
        stale_kind.document.provider_adoptions[0]
            .resource_interface
            .descriptor = Sha256Digest::of_bytes("stale resource kind");
        assert_invalid_adoption(stale_kind, "stale resource kind");
    }

    #[test]
    fn stale_source_and_candidate_grants_fail_closed() {
        let mut stale_source = adoption_authority_fixture();
        let source_binding = stale_source.document.provider_adoptions[0]
            .source
            .handler_binding
            .clone();
        let source_index = stale_source.current.binding_indices[&source_binding];
        stale_source.current.document.bindings[source_index]
            .caller_grant
            .resources
            .clear();
        assert_invalid_adoption(stale_source, "stale source grant");

        let mut stale_candidate = adoption_authority_fixture();
        let candidate_binding = stale_candidate.document.provider_adoptions[0]
            .candidate
            .handler_binding
            .clone();
        let candidate_index = stale_candidate.desired.binding_indices[&candidate_binding];
        stale_candidate.desired.document.bindings[candidate_index]
            .caller_grant
            .resources
            .clear();
        assert_invalid_adoption(stale_candidate, "stale candidate grant");
    }

    #[test]
    fn revoked_or_unavailable_adoption_assignment_fails_closed() {
        for side in [AdoptionSide::Source, AdoptionSide::Candidate] {
            let mut revoked = adoption_authority_fixture();
            adoption_plan_mut(&mut revoked, side)
                .inputs
                .environment
                .providers
                .clear();
            assert_invalid_adoption(revoked, "revoked assignment");

            let mut unavailable = adoption_authority_fixture();
            adoption_plan_mut(&mut unavailable, side)
                .inputs
                .environment
                .providers[0]
                .state = ProviderState::Unavailable;
            assert_invalid_adoption(unavailable, "unavailable assignment");
        }
    }

    #[derive(Clone, Copy)]
    enum AdoptionSide {
        Source,
        Candidate,
    }

    fn assert_endpoint_mutations_fail(side: AdoptionSide) {
        type Mutator = fn(&mut ProviderAdoptionEndpoint);

        let mutations: [(&str, Mutator); 13] = [
            ("owner provider", |endpoint| {
                endpoint.provider.key = key("stale-owner-provider");
            }),
            ("package", |endpoint| {
                endpoint.package = Sha256Digest::of_bytes("stale owner package");
            }),
            ("owner interface", |endpoint| {
                endpoint.interface.descriptor = Sha256Digest::of_bytes("stale owner interface");
            }),
            ("owner implementation", |endpoint| {
                endpoint.implementation.descriptor =
                    Sha256Digest::of_bytes("stale owner implementation");
            }),
            ("state-format artifact", |endpoint| {
                endpoint.state_format.artifact.content =
                    Sha256Digest::of_bytes("unauthenticated state-format artifact");
            }),
            ("state-format descriptor", |endpoint| {
                endpoint.state_format.descriptor =
                    Sha256Digest::of_bytes("stale state-format descriptor");
            }),
            ("handler binding", |endpoint| {
                endpoint.handler_binding = BindingId(key("stale-handler-binding"));
            }),
            ("handler method", |endpoint| {
                endpoint.handler_method = key("stale-handler-method");
            }),
            ("handler provider", |endpoint| {
                endpoint.handler_provider.key = key("stale-handler-provider");
            }),
            ("handler incarnation", |endpoint| {
                endpoint.handler_incarnation =
                    aos_ability_model::IncarnationId::new("stale-handler-incarnation")
                        .expect("valid incarnation");
            }),
            ("handler interface", |endpoint| {
                endpoint.handler_interface.descriptor =
                    Sha256Digest::of_bytes("stale handler interface");
            }),
            ("handler implementation", |endpoint| {
                endpoint.handler_implementation.descriptor =
                    Sha256Digest::of_bytes("stale handler implementation");
            }),
            ("handler package", |endpoint| {
                endpoint.handler_package = Sha256Digest::of_bytes("stale handler package");
            }),
        ];

        for (label, mutate) in mutations {
            let mut fixture = adoption_authority_fixture();
            mutate(adoption_endpoint_mut(&mut fixture, side));
            assert_invalid_adoption(fixture, label);
        }
    }

    fn adoption_endpoint_mut(
        fixture: &mut AuthorityFixture,
        side: AdoptionSide,
    ) -> &mut ProviderAdoptionEndpoint {
        let adoption = &mut fixture.document.provider_adoptions[0];

        match side {
            AdoptionSide::Source => &mut adoption.source,
            AdoptionSide::Candidate => &mut adoption.candidate,
        }
    }

    fn adoption_plan_mut(
        fixture: &mut AuthorityFixture,
        side: AdoptionSide,
    ) -> &mut CheckedBindingPlan {
        match side {
            AdoptionSide::Source => &mut fixture.current,
            AdoptionSide::Candidate => &mut fixture.desired,
        }
    }

    fn assert_invalid_adoption(fixture: AuthorityFixture, label: &str) {
        assert!(
            matches!(
                fixture.validate(),
                Err(TransitionAuthorityError::InvalidDocument(_))
            ),
            "{label} unexpectedly passed adoption authority validation"
        );
    }

    fn adoption_authority_fixture() -> AuthorityFixture {
        let (context, desired, candidate) = multi_export_owner_fixture(true);
        let mut current = desired.clone();
        current.inputs.packages[0].package.version = "0.9.0".to_string();
        let source_package = current.inputs.packages[0]
            .content_digest()
            .expect("source package digest");
        for binding in &mut current.document.bindings {
            binding.provider_package = Some(source_package);
        }
        current.inputs.desired_state.instances[0].package = source_package;
        current.document.desired_state = current
            .inputs
            .desired_state
            .content_digest()
            .expect("source desired-state digest");
        current.id = PlanId(
            current
                .document
                .content_digest()
                .expect("source binding-plan digest"),
        );

        let mut source = candidate.clone();
        source.package = source_package;
        source.handler_package = source_package;
        let handler_binding = desired
            .binding(&candidate.handler_binding)
            .expect("candidate handler binding");
        let resource = handler_binding.caller_grant.resources[0].resource.clone();
        let resource_interface = candidate.handler_interface.clone();
        let desired_planning = Sha256Digest::of_bytes("adoption desired planning");
        let current_planning = Sha256Digest::of_bytes("adoption current planning");
        let policy_revision = desired.document.policy_revision;
        let document = TransitionAuthorizationDocument {
            schema: TransitionAuthorizationDocument::SCHEMA.to_string(),
            required_features: vec![
                RequiredFeature::new(PROVIDER_STATE_ADOPTION_V1).expect("adoption feature"),
            ],
            desired_planning,
            current_planning,
            desired_policy_revision: policy_revision,
            prior_policy_revision: current.document.policy_revision,
            authorization_policy_revision: policy_revision,
            teardown_bindings: Vec::new(),
            teardown_providers: Vec::new(),
            provider_adoptions: vec![ProviderAdoptionAuthorization {
                resource,
                resource_interface,
                source,
                candidate,
            }],
        };

        AuthorityFixture {
            context,
            desired,
            current,
            document,
        }
    }

    fn multi_export_owner_fixture(
        select_owner: bool,
    ) -> (
        ValidationContext,
        CheckedBindingPlan,
        ProviderAdoptionEndpoint,
    ) {
        let mut fixture = crate::test_support::plan_fixture();
        let selected_interface = fixture.binding_plan.bindings[0].interface.clone();
        let provider = fixture.binding_plan.bindings[0].provider.clone();
        let artifact = fixture.binding_plan.bindings[0]
            .implementation
            .artifact
            .clone();
        let handler_key = key("observe-handler");
        let selected_implementation = ProviderImplementation {
            interface: selected_interface.clone(),
            artifact: artifact.clone(),
            requirements: Vec::new(),
            implementation: ImplementationKind::TerminalHandler {
                handler: handler_key.clone(),
            },
            owns_resource_kinds: Vec::new(),
            state_format: None,
        };
        let selected_reference = ProviderImplementationReference {
            descriptor: selected_implementation
                .descriptor_digest()
                .expect("selected implementation digest"),
            artifact: artifact.clone(),
            handler: Some(handler_key.clone()),
        };

        let mut owner_interface = fixture.interfaces[0].clone();
        owner_interface.interface.name =
            InterfaceName::new("test.state-owner").expect("owner interface name");
        for method in owner_interface.interface.methods.values_mut() {
            method.target_resource = owner_interface.interface.name.clone();
        }
        let owner_interface_key = owner_interface
            .interface_key()
            .expect("owner interface digest");
        let state_format = ProviderStateFormat {
            descriptor: Sha256Digest::of_bytes("state-format-v1"),
            artifact: artifact.clone(),
        };
        let owner_implementation = ProviderImplementation {
            interface: owner_interface_key.clone(),
            artifact: artifact.clone(),
            requirements: Vec::new(),
            implementation: ImplementationKind::PureComposition {
                compose_entry: key("compose"),
                transition_entry: key("transition"),
            },
            owns_resource_kinds: vec![selected_interface.name.clone()],
            state_format: Some(state_format.clone()),
        };
        let owner_reference = ProviderImplementationReference {
            descriptor: owner_implementation
                .descriptor_digest()
                .expect("owner implementation digest"),
            artifact: artifact.clone(),
            handler: None,
        };
        let package = PackageDocument {
            schema: PackageDocument::SCHEMA.to_string(),
            required_features: vec![
                RequiredFeature::new("abilities-v1").expect("abilities feature"),
                RequiredFeature::new(aos_ability_model::PROVIDER_STATE_FORMAT_V1)
                    .expect("state-format feature"),
            ],
            activation_mode: AbilityActivationMode::StructuredEffects,
            package: PackageSubject {
                name: key("multi-export-provider"),
                version: "1.0.0".to_string(),
                payload: artifact.clone(),
                source: artifact.clone(),
            },
            artifacts: vec![artifact.clone()],
            exports: vec![
                ExportDeclaration {
                    name: key("handler"),
                    interface: selected_interface.clone(),
                    aggregation: None,
                    implementation: selected_reference.descriptor,
                },
                ExportDeclaration {
                    name: key("owner"),
                    interface: owner_interface_key.clone(),
                    aggregation: None,
                    implementation: owner_reference.descriptor,
                },
            ],
            requirements: Vec::new(),
            module_entry_points: BTreeMap::from([
                (key("compose"), artifact.clone()),
                (key("transition"), artifact.clone()),
            ]),
            implementation: PackageImplementation {
                providers: vec![selected_implementation, owner_implementation],
                handlers: BTreeMap::from([(
                    handler_key,
                    HandlerDescriptor {
                        artifact: artifact.clone(),
                        entry_point: "bin/observe".to_string(),
                        arguments: ValueSchema::Boolean,
                        result: ValueSchema::Boolean,
                    },
                )]),
            },
            ownership: Vec::new(),
        };
        let package_digest = package.content_digest().expect("package digest");
        fixture.binding_plan.bindings[0].provider_package = Some(package_digest);
        fixture.binding_plan.bindings[0].implementation = selected_reference.clone();
        fixture.binding_inputs.environment.providers[0].implementation = selected_reference.clone();
        fixture.binding_inputs.desired_state.instances = vec![DesiredInstance {
            instance: provider.clone(),
            package: package_digest,
            enabled: true,
            configuration: None,
        }];
        fixture.binding_inputs.packages = vec![package];
        if select_owner {
            let handler_scope = ScopePath::new(vec![provider.key.clone(), key("nested")])
                .expect("nested owner scope");
            fixture.binding_inputs.desired_state.child_requests[0]
                .id
                .scope = handler_scope.clone();
            fixture.binding_plan.requests[0].id.scope = handler_scope;
            fixture.binding_plan.bindings[0].request = fixture.binding_plan.requests[0].id.clone();
            fixture.binding_inputs.desired_state.child_requests[0].lifetime =
                aos_ability_model::ResourceLifetime::Persistent;
            fixture.binding_plan.requests[0].lifetime =
                aos_ability_model::ResourceLifetime::Persistent;
            fixture.binding_plan.bindings[0].lifetime =
                aos_ability_model::ResourceLifetime::Persistent;
            fixture.binding_plan.bindings[0].caller_grant.resources[0].access =
                AccessMode::ExclusiveWrite;
            let owner_resource = aos_ability_model::ResourceId {
                provider: provider.clone(),
                key: key("owner-service"),
            };
            let owner_revision = aos_ability_model::ResourceRevision {
                resource: owner_resource.clone(),
                revision: RevisionId(Sha256Digest::of_bytes("owner revision")),
            };
            let owner_request = BindingRequest {
                id: aos_ability_model::RequestId {
                    consumer: provider.clone(),
                    scope: ScopePath::root(),
                    key: key("owner-service"),
                },
                accepted_interfaces: vec![owner_interface_key.clone()],
                methods: vec![key("observe")],
                guarantees: Vec::new(),
                lifetime: aos_ability_model::ResourceLifetime::Persistent,
            };
            let policy_revision = fixture.binding_plan.policy_revision;
            let owner_binding = Binding {
                id: BindingId(key("owner-service")),
                request: owner_request.id.clone(),
                interface: owner_interface_key.clone(),
                provider: provider.clone(),
                provider_package: Some(package_digest),
                implementation: owner_reference.clone(),
                source: aos_ability_model::BindingSource::Explicit,
                caller_grant: aos_ability_model::AuthorityGrant {
                    principal: provider.clone(),
                    methods: vec![key("observe")],
                    contributions: Vec::new(),
                    resources: vec![ResourcePermission {
                        resource: owner_resource.clone(),
                        access: AccessMode::Read,
                        operations: vec![key("observe")],
                    }],
                },
                provider_grant: aos_ability_model::AuthorityGrant {
                    principal: provider.clone(),
                    methods: Vec::new(),
                    contributions: Vec::new(),
                    resources: Vec::new(),
                },
                guarantees: Vec::new(),
                policy_revision,
                lifetime: aos_ability_model::ResourceLifetime::Persistent,
                mediation_allowed: false,
            };
            fixture
                .binding_inputs
                .desired_state
                .child_requests
                .push(owner_request.clone());
            fixture.binding_plan.requests.push(owner_request);
            fixture.binding_plan.bindings.push(owner_binding);
            for revisions in [
                &mut fixture.binding_inputs.environment.resources,
                &mut fixture.binding_inputs.desired_state.resources,
                &mut fixture.binding_plan.resources,
                &mut fixture.effect_plan.current_revisions,
                &mut fixture.effect_plan.desired_revisions,
            ] {
                revisions.push(owner_revision.clone());
                revisions.sort_by(|left, right| {
                    aos_ability_model::compare_resource_ids(&left.resource, &right.resource)
                });
            }
            fixture
                .binding_plan
                .requests
                .sort_by(|left, right| compare_request_ids(&left.id, &right.id));
            fixture
                .binding_inputs
                .desired_state
                .child_requests
                .sort_by(|left, right| compare_request_ids(&left.id, &right.id));
            fixture.binding_plan.bindings.sort_by(|left, right| {
                compare_request_ids(&left.request, &right.request)
                    .then_with(|| left.id.cmp(&right.id))
            });
        }
        fixture.interfaces.push(owner_interface);
        fixture.context = ValidationContext::new(
            BTreeSet::from([
                RequiredFeature::new("abilities-v1").expect("abilities feature"),
                RequiredFeature::new(aos_ability_model::PROVIDER_STATE_FORMAT_V1)
                    .expect("state-format feature"),
            ]),
            fixture.interfaces.clone(),
        )
        .expect("multi-export context");
        fixture.refresh_commitments();
        let checked = fixture
            .context
            .validate_binding_plan(fixture.binding_plan, fixture.binding_inputs)
            .expect("multi-export binding plan");
        let binding = checked
            .bindings()
            .iter()
            .find(|binding| binding.implementation == selected_reference)
            .expect("selected handler binding")
            .clone();
        let incarnation = checked
            .environment()
            .providers
            .iter()
            .find(|inventory| inventory.implementation == selected_reference)
            .expect("selected handler inventory")
            .incarnation
            .clone()
            .expect("available handler incarnation");
        let endpoint = ProviderAdoptionEndpoint {
            provider,
            package: package_digest,
            interface: owner_interface_key,
            implementation: owner_reference,
            state_format,
            handler_binding: binding.id,
            handler_method: key("observe"),
            handler_provider: binding.provider,
            handler_incarnation: incarnation,
            handler_interface: binding.interface,
            handler_implementation: binding.implementation,
            handler_package: package_digest,
        };

        let context = ValidationContext::new(
            BTreeSet::from([
                RequiredFeature::new("abilities-v1").expect("abilities feature"),
                RequiredFeature::new(aos_ability_model::PROVIDER_STATE_FORMAT_V1)
                    .expect("state-format feature"),
                RequiredFeature::new(PROVIDER_STATE_ADOPTION_V1).expect("adoption feature"),
            ]),
            fixture.interfaces,
        )
        .expect("stateful owner context");

        (context, checked, endpoint)
    }

    fn authority_fixture() -> AuthorityFixture {
        let checked = crate::test_support::checked_systemd_manager_effect_plan();
        let context =
            ValidationContext::new(BTreeSet::new(), checked.interfaces().values().cloned())
                .expect("systemd interface catalog must validate");
        let current = checked.binding_plan().clone();
        let desired = current.clone();
        let source = current.bindings()[0].clone();
        let mut request = current.document.requests[0].clone();
        request.id.key = key("transition-stop-old-request");
        let mut binding = source.clone();
        binding.id = BindingId(key("transition-stop-old"));
        binding.request = request.id.clone();
        binding.caller_grant.methods = vec![key("stop")];
        binding.caller_grant.resources[0].access = AccessMode::ExclusiveWrite;
        binding.caller_grant.resources[0].operations = vec![key("stop")];
        binding.provider_grant.methods.clear();
        binding.provider_grant.resources.clear();
        let desired_planning = Sha256Digest::of_bytes("desired planning");
        let current_planning = Sha256Digest::of_bytes("current planning");
        let policy_revision = desired.document.policy_revision;
        let document = TransitionAuthorizationDocument {
            schema: TransitionAuthorizationDocument::SCHEMA.to_string(),
            required_features: Vec::new(),
            desired_planning,
            current_planning,
            desired_policy_revision: policy_revision,
            prior_policy_revision: current.document.policy_revision,
            authorization_policy_revision: policy_revision,
            teardown_bindings: vec![TeardownBindingAuthorization {
                source_binding: source.id,
                request,
                binding,
            }],
            teardown_providers: Vec::new(),
            provider_adoptions: Vec::new(),
        };

        AuthorityFixture {
            context,
            desired,
            current,
            document,
        }
    }

    fn key(value: &str) -> LocalKey {
        LocalKey::new(value).expect("valid test key")
    }
}
