//! Safe selector-lattice authority intersection and authenticated endpoints.

use std::collections::BTreeSet;

use aos_sandbox_core::format::descriptor_for_bytes;
use aos_sandbox_core::{
    Grant, GrantId, MediaType, NetworkEndpointId, ObjectDescriptor, ObjectDigest, Operation,
    OperationSet, PortableMediaType, ResourceId, ResourceKind, Selector,
};
use serde::Serialize;

use super::model::{
    AuthorityPlanCommitmentV1, ExplanationDecisionV1, ExplanationEntryV1, ExplanationReasonV1,
    ExplanationStageV1, InputSourceV1, MAXIMUM_GRANTS_PER_LAYER, PolicyCompilerInputV1,
    PolicyModelError, RedactedSubjectV1, canonical_bytes, digest,
};

/// Selects one closed endpoint use operation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum EndpointUseV1 {
    /// Discovers that the endpoint exists.
    Discover,
    /// Connects or attaches to the endpoint.
    Connect,
    /// Publishes through an ingress endpoint.
    Publish,
}
impl EndpointUseV1 {
    fn operation(self) -> Operation {
        match self {
            Self::Discover => Operation::Discover,
            Self::Connect => Operation::Attach,
            Self::Publish => Operation::Publish,
        }
    }
}

/// Binds one endpoint, capability resource, policy digest, and exact use.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct EndpointCatalogEntryV1 {
    endpoint: NetworkEndpointId,
    resource: ResourceId,
    policy_digest: ObjectDigest,
    required_use: EndpointUseV1,
}
impl EndpointCatalogEntryV1 {
    /// Constructs one endpoint catalog statement.
    #[must_use]
    pub const fn new(
        endpoint: NetworkEndpointId,
        resource: ResourceId,
        policy_digest: ObjectDigest,
        required_use: EndpointUseV1,
    ) -> Self {
        Self {
            endpoint,
            resource,
            policy_digest,
            required_use,
        }
    }
    /// Returns the endpoint identity.
    #[must_use]
    pub const fn endpoint(self) -> NetworkEndpointId {
        self.endpoint
    }
    /// Returns the bound authority resource.
    #[must_use]
    pub const fn resource(self) -> ResourceId {
        self.resource
    }
    /// Returns the exact endpoint policy digest.
    #[must_use]
    pub const fn policy_digest(self) -> ObjectDigest {
        self.policy_digest
    }
    /// Returns the required endpoint use.
    #[must_use]
    pub const fn required_use(self) -> EndpointUseV1 {
        self.required_use
    }
}

/// Verifies an endpoint catalog through an external authenticated authority.
pub trait EndpointCatalogVerifierV1 {
    /// Verifies exact catalog bytes and their descriptor.
    fn verify(&self, descriptor: &ObjectDescriptor, canonical_bytes: &[u8]) -> bool;
}

/// Carries a catalog accepted by an explicit verifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthenticatedEndpointCatalogV1 {
    descriptor: ObjectDescriptor,
    entries: Vec<EndpointCatalogEntryV1>,
}
impl AuthenticatedEndpointCatalogV1 {
    /// Canonicalizes and authenticates endpoint-to-resource relations.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointCatalogError`] for unordered, sentinel, oversized, or
    /// unauthenticated content.
    pub fn authenticate(
        entries: Vec<EndpointCatalogEntryV1>,
        verifier: &impl EndpointCatalogVerifierV1,
    ) -> Result<Self, EndpointCatalogError> {
        if entries.len() > 4_096
            || !entries
                .windows(2)
                .all(|pair| pair[0].endpoint < pair[1].endpoint)
            || entries.iter().any(|entry| {
                entry.endpoint.as_bytes() == &[0; 16]
                    || entry.resource.as_bytes() == &[0; 16]
                    || entry.policy_digest.as_bytes() == &[0; 32]
            })
        {
            return Err(EndpointCatalogError::InvalidCatalog);
        }
        let bytes = canonical_bytes(b"aos.sandbox.endpoint-catalog.v2", &entries)
            .map_err(|_| EndpointCatalogError::InvalidCatalog)?;
        let media = MediaType::new(PortableMediaType::Content.as_str())
            .map_err(|_| EndpointCatalogError::InvalidCatalog)?;
        let descriptor = descriptor_for_bytes(media, &bytes);
        if !verifier.verify(&descriptor, &bytes) {
            return Err(EndpointCatalogError::AuthenticationFailed);
        }
        Ok(Self {
            descriptor,
            entries,
        })
    }
    /// Returns the authenticated catalog descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.descriptor
    }
    /// Returns canonical endpoint bindings.
    #[must_use]
    pub fn entries(&self) -> &[EndpointCatalogEntryV1] {
        &self.entries
    }
}

/// Reports invalid or unauthenticated endpoint catalog input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EndpointCatalogError {
    /// Catalog shape, order, bound, or sentinels are invalid.
    #[error("endpoint catalog is noncanonical or invalid")]
    InvalidCatalog,
    /// The configured authority rejected the exact catalog bytes.
    #[error("endpoint catalog authentication failed")]
    AuthenticationFailed,
}

/// Stores one effective grant and both independent narrowing-cause sets.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EffectiveGrantV1 {
    grant: Grant,
    operation_narrowed_by: Vec<InputSourceV1>,
    delegation_narrowed_by: Vec<InputSourceV1>,
}
impl EffectiveGrantV1 {
    /// Returns the effective grant.
    #[must_use]
    pub const fn grant(&self) -> &Grant {
        &self.grant
    }
    /// Returns every operation-narrowing source.
    #[must_use]
    pub fn operation_narrowed_by(&self) -> &[InputSourceV1] {
        &self.operation_narrowed_by
    }
    /// Returns every delegation-narrowing source.
    #[must_use]
    pub fn delegation_narrowed_by(&self) -> &[InputSourceV1] {
        &self.delegation_narrowed_by
    }
}

/// Stores effective authority and admitted authenticated endpoints.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthorityPlanV1 {
    commitment: AuthorityPlanCommitmentV1,
    grants: Vec<EffectiveGrantV1>,
    endpoints: Vec<EndpointCatalogEntryV1>,
    endpoint_catalog: ObjectDescriptor,
}
impl AuthorityPlanV1 {
    /// Returns the authority commitment.
    #[must_use]
    pub const fn commitment(&self) -> AuthorityPlanCommitmentV1 {
        self.commitment
    }
    /// Returns canonical effective grants.
    #[must_use]
    pub fn grants(&self) -> &[EffectiveGrantV1] {
        &self.grants
    }
    /// Returns admitted endpoint bindings.
    #[must_use]
    pub fn endpoints(&self) -> &[EndpointCatalogEntryV1] {
        &self.endpoints
    }
    /// Returns the authenticated source catalog descriptor.
    #[must_use]
    pub const fn endpoint_catalog(&self) -> &ObjectDescriptor {
        &self.endpoint_catalog
    }
    /// Returns the exact delegable effective-grant subset.
    #[must_use]
    pub fn delegable_grants(&self) -> Vec<Grant> {
        self.grants
            .iter()
            .filter(|item| item.grant.delegable())
            .map(|item| item.grant.clone())
            .collect()
    }
    /// Reports exact kind, operation-set, and selector admission by one grant.
    #[must_use]
    pub fn admits(
        &self,
        kind: ResourceKind,
        operations: OperationSet,
        selector: &Selector,
    ) -> bool {
        self.grants.iter().any(|item| {
            item.grant.resource_kind() == kind
                && operations.is_subset_of(item.grant.operations())
                && item.grant.selector().contains(selector)
        })
    }
    pub(crate) fn admits_effective_grant(
        &self,
        id: GrantId,
        kind: ResourceKind,
        operations: OperationSet,
        selector: &Selector,
    ) -> bool {
        self.grants.iter().any(|item| {
            item.grant.id() == id
                && item.grant.resource_kind() == kind
                && operations.is_subset_of(item.grant.operations())
                && item.grant.selector().contains(selector)
        })
    }
}

pub(crate) fn compile_authority(
    input: &PolicyCompilerInputV1,
) -> Result<(AuthorityPlanV1, Vec<ExplanationEntryV1>), AuthorityCompilationError> {
    let mut effective = Vec::new();
    let mut explanation = Vec::new();
    for requested in input.request().layer().grants() {
        validate_selector(requested.selector())?;
        let mut operations = requested.operations();
        let mut operation_causes = Vec::new();
        let mut delegation_causes = Vec::new();
        let mut denied = false;
        for (source, layer, _) in input.ceiling_layers() {
            let covering = layer
                .grants()
                .iter()
                .filter(|grant| {
                    grant.resource_kind() == requested.resource_kind()
                        && grant.selector().contains(requested.selector())
                })
                .collect::<Vec<_>>();
            let layer_operations = covering.iter().fold(OperationSet::EMPTY, |set, grant| {
                set.union(grant.operations())
            });
            let next = operations.intersection(layer_operations);
            if next != operations {
                operation_causes.push(source);
            }
            operations = next;
            if operations.is_empty() {
                denied = true;
                break;
            }
        }
        let subject = RedactedSubjectV1::for_value(requested)?;
        if denied {
            explanation.push(ExplanationEntryV1::new(
                ExplanationStageV1::Authority,
                ExplanationDecisionV1::Rejected,
                ExplanationReasonV1::DefaultDeny,
                InputSourceV1::Request,
                subject,
                operation_causes,
            ));
            continue;
        }
        // Delegation is evaluated against the final effective operation set.
        // Each ceiling must cover that entire set with one delegable grant;
        // unions are deliberately forbidden for delegation.
        let mut delegable = requested.delegable();
        if delegable {
            for (source, layer, _) in input.ceiling_layers() {
                let singly_covered = layer.grants().iter().any(|grant| {
                    grant.resource_kind() == requested.resource_kind()
                        && grant.selector().contains(requested.selector())
                        && grant.delegable()
                        && operations.is_subset_of(grant.operations())
                });
                if !singly_covered {
                    delegable = false;
                    delegation_causes.push(source);
                }
            }
        }
        let grant = Grant::new(
            requested.id(),
            requested.resource_kind(),
            operations,
            requested.selector().clone(),
            delegable,
        )
        .map_err(|_| AuthorityCompilationError::InvalidGrant)?;
        if operation_causes.is_empty() && delegation_causes.is_empty() {
            explanation.push(ExplanationEntryV1::new(
                ExplanationStageV1::Authority,
                ExplanationDecisionV1::Admitted,
                ExplanationReasonV1::AuthorityAdmitted,
                InputSourceV1::Request,
                subject,
                Vec::new(),
            ));
        } else {
            if !operation_causes.is_empty() {
                explanation.push(ExplanationEntryV1::new(
                    ExplanationStageV1::Authority,
                    ExplanationDecisionV1::Narrowed,
                    ExplanationReasonV1::OperationCeiling,
                    InputSourceV1::Request,
                    subject,
                    operation_causes.clone(),
                ));
            }
            if !delegation_causes.is_empty() {
                explanation.push(ExplanationEntryV1::new(
                    ExplanationStageV1::Authority,
                    ExplanationDecisionV1::Narrowed,
                    ExplanationReasonV1::DelegationCeiling,
                    InputSourceV1::Request,
                    subject,
                    delegation_causes.clone(),
                ));
            }
        }
        effective.push(EffectiveGrantV1 {
            grant,
            operation_narrowed_by: operation_causes,
            delegation_narrowed_by: delegation_causes,
        });
    }
    let mut keyed = effective
        .into_iter()
        .map(|grant| Ok((grant_key(&grant.grant)?, grant)))
        .collect::<Result<Vec<_>, PolicyModelError>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    if keyed
        .windows(2)
        .any(|pair| pair[0].0 == pair[1].0 && pair[0].1 != pair[1].1)
    {
        return Err(AuthorityCompilationError::Model(
            PolicyModelError::CanonicalEncoding,
        ));
    }
    let effective = keyed
        .into_iter()
        .map(|(_, grant)| grant)
        .collect::<Vec<_>>();
    let endpoints = validate_endpoints(input.endpoints(), &effective)?;
    for endpoint in &endpoints {
        explanation.push(ExplanationEntryV1::new(
            ExplanationStageV1::BackendAdmission,
            ExplanationDecisionV1::Admitted,
            ExplanationReasonV1::EndpointAuthority,
            InputSourceV1::Catalog,
            RedactedSubjectV1::for_value(endpoint)?,
            Vec::new(),
        ));
    }
    let endpoint_catalog = input.endpoints().descriptor().clone();
    let commitment = AuthorityPlanCommitmentV1::new(digest(
        b"aos.sandbox.authority-plan.v2",
        &(&effective, &endpoints, &endpoint_catalog),
    )?);
    Ok((
        AuthorityPlanV1 {
            commitment,
            grants: effective,
            endpoints,
            endpoint_catalog,
        },
        explanation,
    ))
}

pub(crate) fn canonicalize_grants(grants: Vec<Grant>) -> Result<Vec<Grant>, PolicyModelError> {
    if grants.len() > MAXIMUM_GRANTS_PER_LAYER {
        return Err(PolicyModelError::TooManyGrants);
    }
    let mut identities = BTreeSet::new();
    let mut semantics = BTreeSet::new();
    for grant in &grants {
        if grant.id().as_bytes() == &[0; 16] {
            return Err(PolicyModelError::AmbiguousIdentity);
        }
        validate_selector(grant.selector()).map_err(|error| match error {
            AuthorityCompilationError::UnsafeSelector => PolicyModelError::UnsafeSelector,
            AuthorityCompilationError::AmbiguousIdentity => PolicyModelError::AmbiguousIdentity,
            _ => PolicyModelError::CanonicalEncoding,
        })?;
        if !identities.insert(grant.id()) {
            return Err(PolicyModelError::DuplicateGrantIdentity);
        }
        let semantic = digest(
            b"aos.sandbox.grant-semantic-key.v1",
            &(
                grant.resource_kind() as u8,
                grant.selector(),
                grant.operations().bits(),
                grant.delegable(),
            ),
        )?;
        if !semantics.insert(semantic) {
            return Err(PolicyModelError::DuplicateSemanticGrant);
        }
    }
    let mut keyed = grants
        .into_iter()
        .map(|grant| Ok((grant_key(&grant)?, grant)))
        .collect::<Result<Vec<_>, PolicyModelError>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    if keyed
        .windows(2)
        .any(|pair| pair[0].0 == pair[1].0 && pair[0].1 != pair[1].1)
    {
        return Err(PolicyModelError::CanonicalEncoding);
    }
    Ok(keyed.into_iter().map(|(_, grant)| grant).collect())
}

fn validate_selector(selector: &Selector) -> Result<(), AuthorityCompilationError> {
    match selector {
        Selector::Profile { .. } => Err(AuthorityCompilationError::UnsafeSelector),
        Selector::Resource { resource } if resource.as_bytes() == &[0; 16] => {
            Err(AuthorityCompilationError::AmbiguousIdentity)
        }
        Selector::Path { export, .. } if export.as_bytes() == &[0; 16] => {
            Err(AuthorityCompilationError::AmbiguousIdentity)
        }
        Selector::Tree { tree } if tree.digest().as_bytes() == &[0; 32] => {
            Err(AuthorityCompilationError::AmbiguousIdentity)
        }
        _ => Ok(()),
    }
}
fn validate_endpoints(
    catalog: &AuthenticatedEndpointCatalogV1,
    effective: &[EffectiveGrantV1],
) -> Result<Vec<EndpointCatalogEntryV1>, AuthorityCompilationError> {
    for entry in catalog.entries() {
        let selector = Selector::Resource {
            resource: entry.resource(),
        };
        if !effective.iter().any(|item| {
            item.grant.resource_kind() == ResourceKind::NetworkEndpoint
                && item
                    .grant
                    .operations()
                    .contains(entry.required_use().operation())
                && item.grant.selector().contains(&selector)
        }) {
            return Err(AuthorityCompilationError::UnauthorizedEndpointUse);
        }
    }
    Ok(catalog.entries().to_vec())
}
fn grant_key(grant: &Grant) -> Result<ObjectDigest, PolicyModelError> {
    digest(
        b"aos.sandbox.grant-order.v2",
        &(
            grant.resource_kind() as u8,
            grant.selector(),
            grant.operations().bits(),
            grant.delegable(),
            grant.id(),
        ),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityCompilationError {
    UnsafeSelector,
    AmbiguousIdentity,
    InvalidGrant,
    UnauthorizedEndpointUse,
    Model(PolicyModelError),
}
impl From<PolicyModelError> for AuthorityCompilationError {
    fn from(value: PolicyModelError) -> Self {
        Self::Model(value)
    }
}
