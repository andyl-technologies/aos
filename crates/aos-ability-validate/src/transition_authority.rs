//! Validation and sealing of fresh authority used while retiring prior state.

use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::document::ProviderState;
use aos_ability_model::{
    Binding, BindingId, ImplementationKind, PackageDocument, PlanId, ResourceLifetime, RevisionId,
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
    for provider in &document.teardown_providers {
        validate_teardown_provider(context, document, inputs, provider)?;
    }
    Ok(())
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
        validate_teardown_binding(context, document, source, source_request, authorization)?;
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
    for grant in [&binding.caller_grant, &binding.provider_grant] {
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
                permission.resource.provider != binding.provider
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
    use aos_ability_model::{
        AccessMode, AggregateId, ContributionPermission, LocalKey, ResourcePermission,
        TeardownBindingAuthorization,
    };

    use super::*;

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
