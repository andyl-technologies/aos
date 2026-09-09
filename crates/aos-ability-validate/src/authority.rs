//! Shared invocation authority checks for planning and fresh runtime admission.

use std::collections::BTreeMap;

use aos_ability_model::{
    AbilityValue, AccessMode, ArtifactReference, AuthorityGrant, AuthorityRole, Binding,
    CredentialAction, InterfaceDocument, InterfaceKey, MethodReference, Operation, OperationFamily,
    ResourceId, ResourceLifetime, ResourceReference, ValueSchema, compare_resource_ids,
};
use serde_json::Value;
use thiserror::Error;

pub(crate) type ArtifactIndex = BTreeMap<aos_contract::Sha256Digest, ArtifactReference>;

/// Reports why an operation method cannot use its selected binding authority.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum InvocationAuthorizationError {
    /// The supplied operation is not an exact member of the checked plan.
    #[error("operation is absent from the checked effect plan")]
    UnknownOperation,
    /// The operation names no binding in the checked binding plan.
    #[error("operation binding is absent from the checked binding plan")]
    UnknownBinding,
    /// The method does not use the binding's exact interface descriptor.
    #[error("method interface differs from the binding's exact descriptor")]
    InterfaceMismatch,
    /// The validated interface catalog does not contain the exact descriptor.
    #[error("method interface is absent from the validated catalog")]
    MissingInterface,
    /// The exact interface does not declare the method.
    #[error("method is absent from the exact interface descriptor")]
    MissingMethod,
    /// The method targets a different resource-interface family.
    #[error("method target differs from the operation's resource interface")]
    TargetMismatch,
    /// The operation requests a resource operation outside the method contract.
    #[error("resource operation projection exceeds the method contract")]
    MethodProjection,
    /// The binding does not permit provider implementation mediation.
    #[error("provider implementation authority requires mediation permission")]
    MediationNotGranted,
    /// The selected caller or provider grant does not name the method.
    #[error("method is absent from the selected authority grant")]
    MethodNotGranted,
    /// The operation target is outside the selected provider's resource scope.
    #[error("operation target is outside the selected provider's resource scope")]
    TargetScopeEscape,
    /// A target projection or declared access exceeds the selected grant.
    #[error("operation resource access exceeds the selected authority grant")]
    ResourceScopeEscape,
}

/// Reports why a materialized value contains an unauthorized typed reference.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ValueAuthorizationError {
    /// A typed reference could not be decoded despite schema validation.
    #[error("materialized typed reference is malformed")]
    MalformedReference,
    /// An artifact reference is absent from the plan's retained catalog.
    #[error("artifact reference is absent from the retained plan catalog")]
    ArtifactNotRetained,
    /// A resource reference names an unknown interface or plan resource.
    #[error("resource reference is absent from the checked catalog or plan")]
    UnknownResource,
    /// A resource reference names another provider or exceeds its binding lifetime.
    #[error("resource reference exceeds its checked provider or lifetime scope")]
    ResourceScopeEscape,
    /// A resource reference's baseline or operation projection exceeds the grant.
    #[error("resource reference exceeds its checked authority grant")]
    ResourceNotGranted,
}

pub(crate) fn authorize_invocation(
    interfaces: &BTreeMap<InterfaceKey, InterfaceDocument>,
    binding: &Binding,
    operation: &Operation,
    method: &MethodReference,
) -> Result<(), InvocationAuthorizationError> {
    if method.interface != binding.interface || operation.interface != binding.interface {
        return Err(InvocationAuthorizationError::InterfaceMismatch);
    }
    let interface = interfaces
        .get(&method.interface)
        .ok_or(InvocationAuthorizationError::MissingInterface)?;
    let descriptor = interface
        .interface
        .methods
        .get(&method.method)
        .ok_or(InvocationAuthorizationError::MissingMethod)?;

    if operation.target.interface != method.interface
        || descriptor.target_resource != operation.target.interface.name
    {
        return Err(InvocationAuthorizationError::TargetMismatch);
    }
    let primary_method = method.method == operation.method;
    if primary_method
        && operation.target.operations.iter().any(|requested| {
            descriptor
                .permitted_operations
                .binary_search(requested)
                .is_err()
        })
    {
        return Err(InvocationAuthorizationError::MethodProjection);
    }

    let grant = invocation_grant(binding, operation.authority)?;
    if grant.methods.binary_search(&method.method).is_err() {
        return Err(InvocationAuthorizationError::MethodNotGranted);
    }
    if operation.target.resource.provider != binding.provider {
        return Err(InvocationAuthorizationError::TargetScopeEscape);
    }
    let required_access = required_target_access(&descriptor.operation_family);
    if !operation.accesses.iter().any(|access| {
        access.resource == operation.target.resource && access.mode.permits(required_access)
    }) {
        return Err(InvocationAuthorizationError::ResourceScopeEscape);
    }
    let required_operations = if primary_method {
        &operation.target.operations
    } else {
        &descriptor.permitted_operations
    };
    if !grant_permits(grant, &operation.target.resource, required_access, None)
        || required_operations.iter().any(|requested| {
            !grant_permits(
                grant,
                &operation.target.resource,
                required_access,
                Some(requested),
            )
        })
        || operation
            .accesses
            .iter()
            .any(|access| !grant_permits(grant, &access.resource, access.mode, None))
    {
        return Err(InvocationAuthorizationError::ResourceScopeEscape);
    }

    Ok(())
}

pub(crate) const fn required_target_access(family: &OperationFamily) -> AccessMode {
    match family {
        OperationFamily::VerifyArtifact
        | OperationFamily::Credential {
            action: CredentialAction::Acquire,
        }
        | OperationFamily::ValidateCandidate
        | OperationFamily::ObserveReadiness => AccessMode::Read,
        OperationFamily::RecordGenerationAssociation => AccessMode::SharedWrite,
        OperationFamily::PrepareManagedConfiguration
        | OperationFamily::Credential {
            action: CredentialAction::Deliver,
        }
        | OperationFamily::PublishConfiguration
        | OperationFamily::PrepareManagerConfiguration
        | OperationFamily::ServiceLifecycle { .. }
        | OperationFamily::ReleaseResource => AccessMode::ExclusiveWrite,
    }
}

fn invocation_grant(
    binding: &Binding,
    authority: AuthorityRole,
) -> Result<&AuthorityGrant, InvocationAuthorizationError> {
    match authority {
        AuthorityRole::Caller => Ok(&binding.caller_grant),
        AuthorityRole::Provider if binding.mediation_allowed => Ok(&binding.provider_grant),
        AuthorityRole::Provider => Err(InvocationAuthorizationError::MediationNotGranted),
    }
}

pub(crate) fn selected_grant(
    binding: &Binding,
    authority: AuthorityRole,
) -> Result<&AuthorityGrant, InvocationAuthorizationError> {
    invocation_grant(binding, authority)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn authorize_materialized_references(
    interfaces: &BTreeMap<InterfaceKey, InterfaceDocument>,
    binding: &Binding,
    grant: &AuthorityGrant,
    schema: &ValueSchema,
    value: &AbilityValue,
    artifacts: &ArtifactIndex,
    resources: &std::collections::BTreeSet<ResourceId>,
    maximum_lifetime: ResourceLifetime,
    required_lifetime: Option<ResourceLifetime>,
) -> Result<(), ValueAuthorizationError> {
    let mut stack = vec![(schema, value.as_json())];
    while let Some((schema, value)) = stack.pop() {
        match (schema, value) {
            (ValueSchema::Optional { .. }, Value::Null) => {}
            (ValueSchema::Optional { value: nested }, value) => stack.push((nested, value)),
            (ValueSchema::ArtifactReference, value) => {
                let reference = serde_json::from_value::<ArtifactReference>(value.clone())
                    .map_err(|_| ValueAuthorizationError::MalformedReference)?;
                if artifacts.get(&reference.content) != Some(&reference) {
                    return Err(ValueAuthorizationError::ArtifactNotRetained);
                }
            }
            (ValueSchema::ResourceReference, value) => {
                let reference = serde_json::from_value::<ResourceReference>(value.clone())
                    .map_err(|_| ValueAuthorizationError::MalformedReference)?;
                authorize_resource_reference(
                    interfaces,
                    binding,
                    grant,
                    &reference,
                    resources,
                    maximum_lifetime,
                    required_lifetime,
                )?;
            }
            (ValueSchema::List { element, .. }, Value::Array(items)) => {
                stack.extend(items.iter().map(|item| (element.as_ref(), item)));
            }
            (ValueSchema::Map { value: nested, .. }, Value::Object(fields)) => {
                stack.extend(fields.values().map(|value| (nested.as_ref(), value)));
            }
            (
                ValueSchema::Record {
                    fields: schemas, ..
                },
                Value::Object(fields),
            ) => {
                for (name, value) in fields {
                    if let Some(field_schema) = schemas.get(name.as_str()) {
                        stack.push((field_schema, value));
                    }
                }
            }
            (ValueSchema::TaggedUnion { tag, variants }, Value::Object(fields)) => {
                if let Some(tag_value) = fields.get(tag.as_str()).and_then(Value::as_str) {
                    if let Some(variant) = variants.get(tag_value) {
                        stack.push((variant, value));
                    }
                }
            }
            _ => {}
        }
    }

    Ok(())
}

fn authorize_resource_reference(
    interfaces: &BTreeMap<InterfaceKey, InterfaceDocument>,
    binding: &Binding,
    grant: &AuthorityGrant,
    reference: &ResourceReference,
    resources: &std::collections::BTreeSet<ResourceId>,
    maximum_lifetime: ResourceLifetime,
    required_lifetime: Option<ResourceLifetime>,
) -> Result<(), ValueAuthorizationError> {
    if !interfaces.contains_key(&reference.interface) || !resources.contains(&reference.resource) {
        return Err(ValueAuthorizationError::UnknownResource);
    }
    if reference.resource.provider != binding.provider
        || reference.lifetime > binding.lifetime
        || reference.lifetime > maximum_lifetime
        || required_lifetime.is_some_and(|required| reference.lifetime < required)
    {
        return Err(ValueAuthorizationError::ResourceScopeEscape);
    }
    if !grant_permits(grant, &reference.resource, AccessMode::Read, None)
        || reference.operations.iter().any(|operation| {
            !grant_permits(
                grant,
                &reference.resource,
                AccessMode::Read,
                Some(operation),
            )
        })
    {
        return Err(ValueAuthorizationError::ResourceNotGranted);
    }

    Ok(())
}

pub(crate) fn grant_permits(
    grant: &AuthorityGrant,
    resource: &aos_ability_model::ResourceId,
    access: aos_ability_model::AccessMode,
    operation: Option<&aos_ability_model::LocalKey>,
) -> bool {
    grant
        .resources
        .binary_search_by(|permission| compare_resource_ids(&permission.resource, resource))
        .ok()
        .map(|index| &grant.resources[index])
        .is_some_and(|permission| {
            permission.access.permits(access)
                && operation
                    .is_none_or(|operation| permission.operations.binary_search(operation).is_ok())
        })
}
