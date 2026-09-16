//! Frozen inputs, compiler limits, explanations, and portable candidate output.
//!
//! Internal commitments use domain-separated length-prefixed bytes over
//! constructor-normalized models. Published policy and optimization objects use
//! the canonical CBOR codecs owned by `aos-sandbox-core`.
//!
//! Internal commitment bytes are:
//!
//! ```text
//! u64be(domain-length) || domain || u64be(payload-length) || canonical-json(payload)
//! ```

use std::collections::BTreeSet;
use std::io::{self, Write};

use aos_sandbox_core::format::{descriptor_for_bytes, encode_optimization, encode_policy};
use aos_sandbox_core::model::{
    CacheDomain, CacheDomainKind, OptimizationProfile, Policy, RevocationPolicy,
};
use aos_sandbox_core::{
    Grant, MediaType, ObjectDescriptor, ObjectDigest, PortableMediaType, ProjectId, SandboxId,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::advisory::{
    AdvisoryActionV1, AdvisoryPlanV1, PortableAdvisoryProgramV1, canonicalize_advisory_actions,
};
use super::authority::{AuthenticatedEndpointCatalogV1, AuthorityPlanV1, canonicalize_grants};
use super::namespace::{
    AuthenticatedNamespaceCatalogV1, NamespacePlanV1, NamespaceRuleV1, PortableNamespaceGraphV1,
    validate_namespace_rule_sequence,
};
use super::resources::{BackendEnforcementSetV1, HardResourcePlanV1, HardResourceProfileV1};

/// Maximum asserted root-to-parent ancestry depth.
pub const MAXIMUM_POLICY_ANCESTORS: usize = 64;
/// Maximum grants in one layer.
pub const MAXIMUM_GRANTS_PER_LAYER: usize = 1_024;
/// Maximum namespace rules in one layer.
pub const MAXIMUM_NAMESPACE_RULES_PER_LAYER: usize = 1_024;
/// Maximum advisory rules in one layer.
pub const MAXIMUM_ADVISORY_RULES_PER_LAYER: usize = 1_024;
/// Maximum frozen bytes for one normalized layer.
pub const MAXIMUM_POLICY_LAYER_BYTES: usize = 8 * 1024 * 1024;
/// Maximum bytes accepted by any internal canonical object encoder.
pub const MAXIMUM_CANONICAL_OBJECT_BYTES: usize = 8 * 1024 * 1024;
/// Maximum complete explanation entries per stage.
pub const MAXIMUM_EXPLANATION_ENTRIES_PER_STAGE: usize = 8_192;
/// Maximum normalization work charged to one policy layer.
pub const MAXIMUM_POLICY_LAYER_WORK_UNITS: u64 = 64 * 1024 * 1024;

macro_rules! commitment_type {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(ObjectDigest);

        impl $name {
            pub(crate) const fn new(digest: ObjectDigest) -> Self {
                Self(digest)
            }

            /// Returns the exact purpose-specific digest.
            #[must_use]
            pub const fn digest(self) -> ObjectDigest {
                self.0
            }
        }
    };
}

commitment_type!(
    NodePolicyCommitmentV1,
    "Commits to frozen node policy input."
);

/// Verifies an exact sandbox-to-project membership statement.
pub trait SandboxProjectRelationVerifierV1 {
    /// Verifies the descriptor and exact canonical relationship bytes.
    fn verify(
        &self,
        sandbox: SandboxId,
        project: ProjectId,
        descriptor: &ObjectDescriptor,
        canonical_bytes: &[u8],
    ) -> bool;
}

/// Carries one externally authenticated sandbox-to-project relationship.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthenticatedSandboxProjectRelationV1 {
    sandbox: SandboxId,
    project: ProjectId,
    descriptor: ObjectDescriptor,
}
impl AuthenticatedSandboxProjectRelationV1 {
    /// Authenticates one exact non-sentinel sandbox and project pair.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyModelError`] when either identity is a sentinel, encoding
    /// fails, or the external authority rejects the exact relationship bytes.
    pub fn authenticate(
        sandbox: SandboxId,
        project: ProjectId,
        verifier: &impl SandboxProjectRelationVerifierV1,
    ) -> Result<Self, PolicyModelError> {
        if sandbox.as_bytes() == &[0; 16] || project.as_bytes() == &[0; 16] {
            return Err(PolicyModelError::AmbiguousIdentity);
        }
        let bytes = canonical_bytes(
            b"aos.sandbox.sandbox-project-relation.v1",
            &(sandbox, project),
        )?;
        let descriptor = descriptor_for_bytes(media_type(PortableMediaType::Content)?, &bytes);
        if !verifier.verify(sandbox, project, &descriptor, &bytes) {
            return Err(PolicyModelError::SandboxProjectAuthenticationFailed);
        }
        Ok(Self {
            sandbox,
            project,
            descriptor,
        })
    }
    /// Returns the authenticated sandbox identity.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }
    /// Returns the authenticated project identity.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }
    /// Returns the exact authenticated relation descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.descriptor
    }
}
commitment_type!(
    SitePolicyCommitmentV1,
    "Commits to frozen site policy input."
);
commitment_type!(
    ProjectPolicyCommitmentV1,
    "Commits to project-branded policy input."
);
commitment_type!(
    AncestorPolicyCommitmentV1,
    "Commits to ordinal-branded ancestor input."
);
commitment_type!(
    RequestPolicyCommitmentV1,
    "Commits to frozen request policy input."
);
commitment_type!(AuthorityPlanCommitmentV1, "Commits to effective authority.");
commitment_type!(
    NamespacePlanCommitmentV1,
    "Commits to the canonical namespace plan."
);
commitment_type!(
    HardResourcePlanCommitmentV1,
    "Commits to all resolved hard resources."
);
commitment_type!(
    AdvisoryPlanCommitmentV1,
    "Commits to all advisory decisions."
);
commitment_type!(
    ExplanationCommitmentV1,
    "Commits to complete per-stage explanation."
);
commitment_type!(
    CompiledPolicyCommitmentV1,
    "Commits to the complete inert candidate."
);

/// Binds a cache-disclosure domain to its authority identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum CacheDomainBindingV1 {
    /// Binds private disclosure to the target sandbox.
    Sandbox(SandboxId),
    /// Binds project disclosure to the target project.
    Project(ProjectId),
    /// Attests that the exact target project belongs to a trust domain.
    TrustDomain(ProjectId),
    /// Identifies the sole unauthenticated public exception.
    Public,
}

/// Verifies exact cache-domain binding bytes through an external authority.
pub trait CacheDomainVerifierV1 {
    /// Verifies the exact descriptor and canonical binding bytes.
    fn verify(&self, descriptor: &ObjectDescriptor, canonical_bytes: &[u8]) -> bool;
}

/// Carries a cache domain whose non-public authority binding was authenticated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthenticatedCacheDomainV1 {
    domain: CacheDomain,
    binding: CacheDomainBindingV1,
    descriptor: ObjectDescriptor,
}
impl AuthenticatedCacheDomainV1 {
    /// Authenticates one non-public domain and exact authority binding.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyModelError`] for a mismatched kind, public bypass, encoding
    /// failure, or rejected authentication.
    pub fn authenticate(
        domain: CacheDomain,
        binding: CacheDomainBindingV1,
        verifier: &impl CacheDomainVerifierV1,
    ) -> Result<Self, PolicyModelError> {
        if domain.domain_id().as_bytes() == &[0; 16]
            || !matches!(
                (domain.kind(), binding),
                (CacheDomainKind::Private, CacheDomainBindingV1::Sandbox(_))
                    | (CacheDomainKind::Project, CacheDomainBindingV1::Project(_))
                    | (
                        CacheDomainKind::TrustDomain,
                        CacheDomainBindingV1::TrustDomain(_)
                    )
            )
        {
            return Err(PolicyModelError::InvalidCacheDomainBinding);
        }
        let bytes = canonical_bytes(b"aos.sandbox.cache-domain-binding.v2", &(domain, binding))?;
        let descriptor = descriptor_for_bytes(media_type(PortableMediaType::Content)?, &bytes);
        if !verifier.verify(&descriptor, &bytes) {
            return Err(PolicyModelError::CacheDomainAuthenticationFailed);
        }
        Ok(Self {
            domain,
            binding,
            descriptor,
        })
    }

    /// Constructs the explicit unauthenticated public-domain exception.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyModelError::InvalidCacheDomainBinding`] unless the domain is public.
    pub fn public(domain: CacheDomain) -> Result<Self, PolicyModelError> {
        if domain.kind() != CacheDomainKind::Public || domain.domain_id().as_bytes() == &[0; 16] {
            return Err(PolicyModelError::InvalidCacheDomainBinding);
        }
        let binding = CacheDomainBindingV1::Public;
        let bytes = canonical_bytes(b"aos.sandbox.cache-domain-binding.v2", &(domain, binding))?;
        let descriptor = descriptor_for_bytes(media_type(PortableMediaType::Content)?, &bytes);
        Ok(Self {
            domain,
            binding,
            descriptor,
        })
    }
    /// Returns the bound core domain.
    #[must_use]
    pub const fn domain(&self) -> CacheDomain {
        self.domain
    }
    /// Returns the authority binding.
    #[must_use]
    pub const fn binding(&self) -> CacheDomainBindingV1 {
        self.binding
    }
    /// Returns the exact binding descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.descriptor
    }
    fn validates_target(&self, sandbox: SandboxId, project: ProjectId) -> bool {
        match self.binding {
            CacheDomainBindingV1::Sandbox(candidate) => {
                candidate == sandbox && self.domain.domain_id().as_bytes() == sandbox.as_bytes()
            }
            CacheDomainBindingV1::Project(candidate) => {
                candidate == project && self.domain.domain_id().as_bytes() == project.as_bytes()
            }
            CacheDomainBindingV1::TrustDomain(candidate) => {
                candidate == project && self.domain.kind() == CacheDomainKind::TrustDomain
            }
            CacheDomainBindingV1::Public => self.domain.kind() == CacheDomainKind::Public,
        }
    }
}

/// Selects an inherited or exact cache-disclosure ceiling.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum CacheDomainInputV1 {
    /// Defers to another layer.
    Inherit,
    /// Supplies an exact ceiling.
    Exact(AuthenticatedCacheDomainV1),
}

/// Selects inherited or exact revocation behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum RevocationInputV1 {
    /// Defers to another layer.
    Inherit,
    /// Supplies exact behavior.
    Exact(RevocationPolicy),
}

/// Stores one normalized policy layer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PolicyLayerV1 {
    grants: Vec<Grant>,
    resources: HardResourceProfileV1,
    namespace_rules: Vec<NamespaceRuleV1>,
    advisory_actions: Vec<AdvisoryActionV1>,
    cache_domain: CacheDomainInputV1,
    revocation: RevocationInputV1,
}

impl PolicyLayerV1 {
    /// Constructs and freezes all set and sequence invariants for one layer.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyModelError`] for duplicate, ambiguous, noncanonical, or
    /// oversized content.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        grants: Vec<Grant>,
        resources: HardResourceProfileV1,
        namespace_rules: Vec<NamespaceRuleV1>,
        advisory_actions: Vec<AdvisoryActionV1>,
        cache_domain: CacheDomainInputV1,
        revocation: RevocationInputV1,
    ) -> Result<Self, PolicyModelError> {
        if namespace_rules.len() > MAXIMUM_NAMESPACE_RULES_PER_LAYER {
            return Err(PolicyModelError::TooManyNamespaceRules);
        }
        if advisory_actions.len() > MAXIMUM_ADVISORY_RULES_PER_LAYER {
            return Err(PolicyModelError::TooManyAdvisoryRules);
        }
        preflight_layer(
            &grants,
            &resources,
            &namespace_rules,
            &advisory_actions,
            &cache_domain,
            revocation,
        )?;
        let layer = Self {
            grants: canonicalize_grants(grants)?,
            resources,
            namespace_rules: validate_namespace_rule_sequence(namespace_rules)?,
            advisory_actions: canonicalize_advisory_actions(advisory_actions)?,
            cache_domain,
            revocation,
        };
        if canonical_bytes(b"aos.sandbox.policy-layer.v2", &layer)?.len()
            > MAXIMUM_POLICY_LAYER_BYTES
        {
            return Err(PolicyModelError::PolicyLayerTooLarge);
        }
        Ok(layer)
    }

    /// Returns canonical grants.
    #[must_use]
    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }
    /// Returns complete hard-resource input.
    #[must_use]
    pub const fn resources(&self) -> &HardResourceProfileV1 {
        &self.resources
    }
    /// Returns namespace rules in semantic order.
    #[must_use]
    pub fn namespace_rules(&self) -> &[NamespaceRuleV1] {
        &self.namespace_rules
    }
    /// Returns canonical advisory rules.
    #[must_use]
    pub fn advisory_actions(&self) -> &[AdvisoryActionV1] {
        &self.advisory_actions
    }
    /// Returns the cache ceiling input.
    #[must_use]
    pub const fn cache_domain(&self) -> &CacheDomainInputV1 {
        &self.cache_domain
    }
    /// Returns the revocation input.
    #[must_use]
    pub const fn revocation(&self) -> RevocationInputV1 {
        self.revocation
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct FrozenLayerV1<C> {
    commitment: C,
    descriptor: ObjectDescriptor,
    bytes: Vec<u8>,
    layer: PolicyLayerV1,
}

fn freeze<C>(
    domain: &'static [u8],
    value: impl Serialize,
    layer: PolicyLayerV1,
    wrap: impl FnOnce(ObjectDigest) -> C,
) -> Result<FrozenLayerV1<C>, PolicyModelError> {
    let bytes = canonical_bytes(domain, &value)?;
    if bytes.len() > MAXIMUM_POLICY_LAYER_BYTES {
        return Err(PolicyModelError::PolicyLayerTooLarge);
    }
    let descriptor = descriptor_for_bytes(media_type(PortableMediaType::Content)?, &bytes);
    Ok(FrozenLayerV1 {
        commitment: wrap(descriptor.digest()),
        descriptor,
        bytes,
        layer,
    })
}

macro_rules! simple_input {
    ($name:ident, $commit:ident, $domain:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
        pub struct $name(FrozenLayerV1<$commit>);

        impl $name {
            /// Freezes one normalized layer in its purpose domain.
            ///
            /// # Errors
            ///
            /// Returns [`PolicyModelError`] for encoding, descriptor, or size failure.
            pub fn new(layer: PolicyLayerV1) -> Result<Self, PolicyModelError> {
                freeze($domain, &layer, layer.clone(), $commit::new).map(Self)
            }
            /// Returns the purpose commitment.
            #[must_use]
            pub const fn commitment(&self) -> $commit {
                self.0.commitment
            }
            /// Returns the exact input descriptor.
            #[must_use]
            pub const fn descriptor(&self) -> &ObjectDescriptor {
                &self.0.descriptor
            }
            /// Returns exact frozen bytes.
            #[must_use]
            pub fn canonical_bytes(&self) -> &[u8] {
                &self.0.bytes
            }
            /// Returns normalized semantics.
            #[must_use]
            pub const fn layer(&self) -> &PolicyLayerV1 {
                &self.0.layer
            }
        }
    };
}

simple_input!(
    NodePolicyInputV1,
    NodePolicyCommitmentV1,
    b"aos.sandbox.policy-input.node.v2",
    "Stores frozen node input."
);
simple_input!(
    SitePolicyInputV1,
    SitePolicyCommitmentV1,
    b"aos.sandbox.policy-input.site.v2",
    "Stores frozen site input."
);
simple_input!(
    RequestPolicyInputV1,
    RequestPolicyCommitmentV1,
    b"aos.sandbox.policy-input.request.v2",
    "Stores frozen request input."
);

/// Stores frozen project-branded input.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProjectPolicyInputV1 {
    project: ProjectId,
    frozen: FrozenLayerV1<ProjectPolicyCommitmentV1>,
}

impl ProjectPolicyInputV1 {
    /// Freezes a project identity and layer together.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyModelError`] for encoding, descriptor, or size failure.
    pub fn new(project: ProjectId, layer: PolicyLayerV1) -> Result<Self, PolicyModelError> {
        if project.as_bytes() == &[0; 16] {
            return Err(PolicyModelError::AmbiguousIdentity);
        }
        let frozen = freeze(
            b"aos.sandbox.policy-input.project.v2",
            (project, &layer),
            layer.clone(),
            ProjectPolicyCommitmentV1::new,
        )?;
        Ok(Self { project, frozen })
    }
    /// Returns the project identity.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }
    /// Returns the purpose commitment.
    #[must_use]
    pub const fn commitment(&self) -> ProjectPolicyCommitmentV1 {
        self.frozen.commitment
    }
    /// Returns the frozen descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.frozen.descriptor
    }
    /// Returns exact frozen bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.frozen.bytes
    }
    /// Returns normalized semantics.
    #[must_use]
    pub const fn layer(&self) -> &PolicyLayerV1 {
        &self.frozen.layer
    }
}

/// Stores one ordinal-branded asserted ancestor input.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AncestorPolicyInputV1 {
    sandbox: SandboxId,
    ordinal: u16,
    frozen: FrozenLayerV1<AncestorPolicyCommitmentV1>,
}

impl AncestorPolicyInputV1 {
    fn new(
        sandbox: SandboxId,
        ordinal: u16,
        layer: PolicyLayerV1,
    ) -> Result<Self, PolicyModelError> {
        let frozen = freeze(
            b"aos.sandbox.policy-input.ancestor.v2",
            (sandbox, ordinal, &layer),
            layer.clone(),
            AncestorPolicyCommitmentV1::new,
        )?;
        Ok(Self {
            sandbox,
            ordinal,
            frozen,
        })
    }
    /// Returns the ancestor identity.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }
    /// Returns the root-to-parent ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }
    /// Returns the commitment.
    #[must_use]
    pub const fn commitment(&self) -> AncestorPolicyCommitmentV1 {
        self.frozen.commitment
    }
    /// Returns the descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.frozen.descriptor
    }
    /// Returns exact frozen bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.frozen.bytes
    }
    /// Returns normalized semantics.
    #[must_use]
    pub const fn layer(&self) -> &PolicyLayerV1 {
        &self.frozen.layer
    }
}

/// Selects one closed namespace backend semantic.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum NamespaceBackendFeatureV1 {
    /// Immutable presentation.
    Immutable,
    /// Generation-fenced native live read.
    LiveReadOnly,
    /// Direct writable presentation.
    ReadWrite,
    /// Private copy-on-write presentation.
    PrivateCow,
    /// Append-only staging.
    AppendOnly,
    /// Mediated service presentation.
    Service,
    /// Registered metadata presentation.
    MetadataPresentation,
    /// Enforced ordinary-view noexec semantics.
    NoExecute,
}

/// Stores typed backend availability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BackendCapabilitiesV1 {
    enforcement: BackendEnforcementSetV1,
    namespace: Vec<NamespaceBackendFeatureV1>,
    advisory: Vec<super::advisory::AdvisoryKindV1>,
    descriptor: ObjectDescriptor,
}

impl BackendCapabilitiesV1 {
    /// Constructs canonical typed availability sets.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyModelError::SetNotCanonical`] for unordered or duplicate sets.
    pub fn new(
        enforcement: BackendEnforcementSetV1,
        namespace: Vec<NamespaceBackendFeatureV1>,
        advisory: Vec<super::advisory::AdvisoryKindV1>,
    ) -> Result<Self, PolicyModelError> {
        if !increasing(&namespace) || !increasing(&advisory) {
            return Err(PolicyModelError::SetNotCanonical);
        }
        let bytes = canonical_bytes(
            b"aos.sandbox.backend-capabilities.v2",
            &(&enforcement, &namespace, &advisory),
        )?;
        let descriptor = descriptor_for_bytes(media_type(PortableMediaType::Content)?, &bytes);
        Ok(Self {
            enforcement,
            namespace,
            advisory,
            descriptor,
        })
    }
    /// Returns hard enforcement mechanisms.
    #[must_use]
    pub const fn enforcement(&self) -> &BackendEnforcementSetV1 {
        &self.enforcement
    }
    /// Returns namespace backend semantics.
    #[must_use]
    pub fn namespace(&self) -> &[NamespaceBackendFeatureV1] {
        &self.namespace
    }
    /// Returns supported advisory kinds.
    #[must_use]
    pub fn advisory(&self) -> &[super::advisory::AdvisoryKindV1] {
        &self.advisory
    }
    /// Returns the exact frozen backend-capability descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.descriptor
    }
}

/// Defines compiler-wide work limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct PolicyCompilerLimitsV1 {
    work: u64,
    dag_depth: u16,
    rules: usize,
}

impl PolicyCompilerLimitsV1 {
    /// Conservative default budget.
    pub const DEFAULT: Self = Self {
        work: 2_000_000,
        dag_depth: 128,
        rules: 16_384,
    };
    /// Constructs nonzero limits.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyModelError::InvalidCompilerLimits`] for zero.
    pub const fn new(work: u64, dag_depth: u16, rules: usize) -> Result<Self, PolicyModelError> {
        if work == 0 || dag_depth == 0 || rules == 0 {
            Err(PolicyModelError::InvalidCompilerLimits)
        } else {
            Ok(Self {
                work,
                dag_depth,
                rules,
            })
        }
    }
    /// Returns the work-unit limit.
    #[must_use]
    pub const fn work(self) -> u64 {
        self.work
    }
    /// Returns the DAG-depth limit.
    #[must_use]
    pub const fn dag_depth(self) -> u16 {
        self.dag_depth
    }
    /// Returns the total-rule limit.
    #[must_use]
    pub const fn rules(self) -> usize {
        self.rules
    }
}

/// Stores fixed-order compiler input and branded catalogs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PolicyCompilerInputV1 {
    relation: AuthenticatedSandboxProjectRelationV1,
    node: NodePolicyInputV1,
    site: SitePolicyInputV1,
    project: ProjectPolicyInputV1,
    ancestors: Vec<AncestorPolicyInputV1>,
    request: RequestPolicyInputV1,
    endpoints: AuthenticatedEndpointCatalogV1,
    destinations: AuthenticatedNamespaceCatalogV1,
    backend: BackendCapabilitiesV1,
    limits: PolicyCompilerLimitsV1,
}

impl PolicyCompilerInputV1 {
    /// Constructs bounded node-to-request input.
    ///
    /// Ancestry is explicitly asserted, not authority-verified, in this
    /// foundation partition. The output is therefore nonauthoritative.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyModelError`] for a sentinel target, duplicate/excessive
    /// ancestry, total-rule overflow, or a cache binding that does not match
    /// the exact target sandbox and project.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        relation: AuthenticatedSandboxProjectRelationV1,
        node: NodePolicyInputV1,
        site: SitePolicyInputV1,
        project: ProjectPolicyInputV1,
        ancestors: Vec<(SandboxId, PolicyLayerV1)>,
        request: RequestPolicyInputV1,
        endpoints: AuthenticatedEndpointCatalogV1,
        destinations: AuthenticatedNamespaceCatalogV1,
        backend: BackendCapabilitiesV1,
        limits: PolicyCompilerLimitsV1,
    ) -> Result<Self, PolicyModelError> {
        let sandbox = relation.sandbox();
        if relation.project() != project.project() {
            return Err(PolicyModelError::SandboxProjectMismatch);
        }
        if ancestors.len() > MAXIMUM_POLICY_ANCESTORS {
            return Err(PolicyModelError::TooManyAncestors);
        }
        let mut seen = BTreeSet::new();
        let mut frozen = Vec::with_capacity(ancestors.len());
        for (index, (sandbox, layer)) in ancestors.into_iter().enumerate() {
            if sandbox.as_bytes() == &[0; 16] {
                return Err(PolicyModelError::AmbiguousIdentity);
            }
            if !seen.insert(sandbox) {
                return Err(PolicyModelError::DuplicateAncestor);
            }
            let ordinal = u16::try_from(index).map_err(|_| PolicyModelError::TooManyAncestors)?;
            frozen.push(AncestorPolicyInputV1::new(sandbox, ordinal, layer)?);
        }
        let layers = [
            &node.0.layer,
            &site.0.layer,
            project.layer(),
            &request.0.layer,
        ]
        .into_iter()
        .chain(frozen.iter().map(AncestorPolicyInputV1::layer));
        let mut count = 0_usize;
        for layer in layers {
            count = count
                .checked_add(layer.grants.len())
                .and_then(|value| value.checked_add(layer.namespace_rules.len()))
                .and_then(|value| value.checked_add(layer.advisory_actions.len()))
                .ok_or(PolicyModelError::CompilerInputTooLarge)?;
        }
        count = count
            .checked_add(endpoints.entries().len())
            .and_then(|value| value.checked_add(destinations.entries().len()))
            .ok_or(PolicyModelError::CompilerInputTooLarge)?;
        if count > limits.rules() {
            return Err(PolicyModelError::CompilerInputTooLarge);
        }
        let target_project = project.project();
        let cache_bindings_valid = [node.layer(), site.layer(), project.layer(), request.layer()]
            .into_iter()
            .chain(frozen.iter().map(AncestorPolicyInputV1::layer))
            .all(|layer| match layer.cache_domain() {
                CacheDomainInputV1::Inherit => true,
                CacheDomainInputV1::Exact(domain) => {
                    domain.validates_target(sandbox, target_project)
                }
            });
        if !cache_bindings_valid {
            return Err(PolicyModelError::InvalidCacheDomainBinding);
        }
        Ok(Self {
            relation,
            node,
            site,
            project,
            ancestors: frozen,
            request,
            endpoints,
            destinations,
            backend,
            limits,
        })
    }

    pub(crate) fn ceiling_layers(
        &self,
    ) -> impl Iterator<Item = (InputSourceV1, &PolicyLayerV1, ObjectDigest)> {
        [
            (
                InputSourceV1::Node,
                self.node.layer(),
                self.node.commitment().digest(),
            ),
            (
                InputSourceV1::Site,
                self.site.layer(),
                self.site.commitment().digest(),
            ),
            (
                InputSourceV1::Project,
                self.project.layer(),
                self.project.commitment().digest(),
            ),
        ]
        .into_iter()
        .chain(self.ancestors.iter().map(|ancestor| {
            (
                InputSourceV1::Ancestor {
                    ordinal: ancestor.ordinal(),
                },
                ancestor.layer(),
                ancestor.commitment().digest(),
            )
        }))
    }
    pub(crate) fn all_layers(
        &self,
    ) -> impl Iterator<Item = (InputSourceV1, &PolicyLayerV1, ObjectDigest)> {
        self.ceiling_layers().chain([(
            InputSourceV1::Request,
            self.request.layer(),
            self.request.commitment().digest(),
        )])
    }
    /// Returns the exact target sandbox identity.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.relation.sandbox()
    }
    /// Returns the authenticated sandbox-to-project relationship.
    #[must_use]
    pub const fn relation(&self) -> &AuthenticatedSandboxProjectRelationV1 {
        &self.relation
    }
    /// Returns the node ceiling input.
    #[must_use]
    pub const fn node(&self) -> &NodePolicyInputV1 {
        &self.node
    }
    /// Returns the site ceiling input.
    #[must_use]
    pub const fn site(&self) -> &SitePolicyInputV1 {
        &self.site
    }
    /// Returns the project ceiling input.
    #[must_use]
    pub const fn project(&self) -> &ProjectPolicyInputV1 {
        &self.project
    }
    /// Returns the request input.
    #[must_use]
    pub const fn request(&self) -> &RequestPolicyInputV1 {
        &self.request
    }
    /// Returns asserted ancestors in root-to-parent order.
    #[must_use]
    pub fn ancestors(&self) -> &[AncestorPolicyInputV1] {
        &self.ancestors
    }
    /// Returns the authenticated endpoint catalog.
    #[must_use]
    pub const fn endpoints(&self) -> &AuthenticatedEndpointCatalogV1 {
        &self.endpoints
    }
    /// Returns the authenticated namespace catalog.
    #[must_use]
    pub const fn destinations(&self) -> &AuthenticatedNamespaceCatalogV1 {
        &self.destinations
    }
    /// Returns typed backend availability.
    #[must_use]
    pub const fn backend(&self) -> &BackendCapabilitiesV1 {
        &self.backend
    }
    /// Returns compiler limits.
    #[must_use]
    pub const fn limits(&self) -> PolicyCompilerLimitsV1 {
        self.limits
    }
    pub(crate) fn descriptors(&self) -> Vec<ObjectDescriptor> {
        let mut values = vec![
            self.node.descriptor().clone(),
            self.site.descriptor().clone(),
            self.project.descriptor().clone(),
        ];
        values.extend(
            self.ancestors
                .iter()
                .map(|ancestor| ancestor.descriptor().clone()),
        );
        values.push(self.request.descriptor().clone());
        values
    }
}

/// Marks the result as unusable for publication authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateAuthorityV1 {
    /// Root-to-parent ancestry has not been authority-verified.
    NonAuthoritativeAncestry,
}

/// Identifies one fixed compiler stage.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ExplanationStageV1 {
    /// Freezes and validates all inputs.
    Normalize,
    /// Intersects capability authority.
    Authority,
    /// Resolves the logical namespace graph.
    Namespace,
    /// Resolves hard limits and disclosure/revocation ceilings.
    HardResources,
    /// Proves required backend semantics.
    BackendAdmission,
    /// Selects or explicitly degrades optimization advice.
    Advisory,
    /// Encodes and commits portable outputs.
    Lowering,
}
/// Classifies a compiler decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum ExplanationDecisionV1 {
    /// Accepts a request without narrowing.
    Admitted,
    /// Accepts a strictly reduced request.
    Narrowed,
    /// Denies a request.
    Rejected,
    /// Records a mandatory mechanism or bound.
    Required,
    /// Explicitly omits advisory behavior.
    Degraded,
    /// Commits immutable canonical bytes.
    Frozen,
}
/// Gives a stable machine-readable reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum ExplanationReasonV1 {
    /// Records one canonical input object.
    InputFrozen,
    /// Applies default-deny authority.
    DefaultDeny,
    /// Records authority admitted without narrowing.
    AuthorityAdmitted,
    /// Attributes operation attenuation.
    OperationCeiling,
    /// Attributes delegation attenuation.
    DelegationCeiling,
    /// Proves logical-source authority.
    NamespaceSource,
    /// Proves attachment-destination authority.
    DestinationAuthority,
    /// Records canonical composition.
    NamespaceComposition,
    /// Records presentation semantics.
    NamespacePresentation,
    /// Records an enforced noexec denial.
    NamespaceNoExecute,
    /// Records verified executable presentation and derived Execute authority.
    NamespaceExecute,
    /// Attributes a hard-limit result to all explicit layers.
    ResourceProvenance,
    /// Attributes cache-domain containment.
    CacheDomainCeiling,
    /// Attributes revocation intersection.
    RevocationCeiling,
    /// Requires a typed hard-enforcement mechanism.
    BackendEnforcement,
    /// Requires a registered backend feature.
    BackendFeature,
    /// Proves an authenticated endpoint binding.
    EndpointAuthority,
    /// Selects admitted advice.
    AdvisorySelected,
    /// Records explicit advisory omission.
    AdvisoryDegraded,
    /// Commits the complete portable output bundle.
    PortableLowering,
}
/// Identifies a source without disclosing its contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum InputSourceV1 {
    /// Node safety policy.
    Node,
    /// Site policy.
    Site,
    /// Project policy.
    Project,
    /// One asserted root-to-parent ancestor.
    Ancestor {
        /// Zero-based root-to-parent ordinal.
        ordinal: u16,
    },
    /// Authenticated caller request.
    Request,
    /// Authenticated catalog input.
    Catalog,
    /// Observed typed backend capabilities.
    Backend,
    /// Deterministic compiler derivation.
    Compiler,
}

/// Stores a nonreversible explanation subject.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RedactedSubjectV1(ObjectDigest);
impl RedactedSubjectV1 {
    pub(crate) fn for_value<T: Serialize>(value: &T) -> Result<Self, PolicyModelError> {
        digest(b"aos.sandbox.policy-explanation.subject.v2", value).map(Self)
    }
    /// Returns the subject digest.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.0
    }
}

/// Stores one complete redacted decision and every narrowing cause.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExplanationEntryV1 {
    stage: ExplanationStageV1,
    decision: ExplanationDecisionV1,
    reason: ExplanationReasonV1,
    source: InputSourceV1,
    subject: RedactedSubjectV1,
    causes: Vec<InputSourceV1>,
}
impl ExplanationEntryV1 {
    pub(crate) fn new(
        stage: ExplanationStageV1,
        decision: ExplanationDecisionV1,
        reason: ExplanationReasonV1,
        source: InputSourceV1,
        subject: RedactedSubjectV1,
        causes: Vec<InputSourceV1>,
    ) -> Self {
        Self {
            stage,
            decision,
            reason,
            source,
            subject,
            causes,
        }
    }
    /// Returns the stage.
    #[must_use]
    pub const fn stage(&self) -> ExplanationStageV1 {
        self.stage
    }
    /// Returns the decision.
    #[must_use]
    pub const fn decision(&self) -> ExplanationDecisionV1 {
        self.decision
    }
    /// Returns the reason.
    #[must_use]
    pub const fn reason(&self) -> ExplanationReasonV1 {
        self.reason
    }
    /// Returns the source.
    #[must_use]
    pub const fn source(&self) -> InputSourceV1 {
        self.source
    }
    /// Returns the subject.
    #[must_use]
    pub const fn subject(&self) -> RedactedSubjectV1 {
        self.subject
    }
    /// Returns all narrowing causes.
    #[must_use]
    pub fn causes(&self) -> &[InputSourceV1] {
        &self.causes
    }
}

/// Stores complete entries for one stage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StageExplanationV1 {
    stage: ExplanationStageV1,
    entries: Vec<ExplanationEntryV1>,
}
impl StageExplanationV1 {
    pub(crate) fn new(
        stage: ExplanationStageV1,
        entries: Vec<ExplanationEntryV1>,
    ) -> Result<Self, PolicyModelError> {
        if entries.len() > MAXIMUM_EXPLANATION_ENTRIES_PER_STAGE
            || entries.iter().any(|entry| entry.stage() != stage)
        {
            return Err(PolicyModelError::ExplanationTooLarge);
        }
        Ok(Self { stage, entries })
    }
    /// Returns the stage.
    #[must_use]
    pub const fn stage(&self) -> ExplanationStageV1 {
        self.stage
    }
    /// Returns every decision without truncation.
    #[must_use]
    pub fn entries(&self) -> &[ExplanationEntryV1] {
        &self.entries
    }
}

/// Stores all seven explanation stages in order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PlanExplanationV1 {
    commitment: ExplanationCommitmentV1,
    stages: Vec<StageExplanationV1>,
}
impl PlanExplanationV1 {
    pub(crate) fn new(stages: Vec<StageExplanationV1>) -> Result<Self, PolicyModelError> {
        if stages.len() != 7
            || !stages
                .windows(2)
                .all(|pair| pair[0].stage() < pair[1].stage())
        {
            return Err(PolicyModelError::IncompleteExplanation);
        }
        let commitment =
            ExplanationCommitmentV1::new(digest(b"aos.sandbox.policy-explanation.v2", &stages)?);
        Ok(Self { commitment, stages })
    }
    /// Returns the commitment.
    #[must_use]
    pub const fn commitment(&self) -> ExplanationCommitmentV1 {
        self.commitment
    }
    /// Returns all stages.
    #[must_use]
    pub fn stages(&self) -> &[StageExplanationV1] {
        &self.stages
    }
}

/// Stores canonical core policy and optimization objects and descriptors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortablePolicyOutputV1 {
    policy: Policy,
    policy_bytes: Vec<u8>,
    policy_descriptor: ObjectDescriptor,
    optimization: OptimizationProfile,
    optimization_bytes: Vec<u8>,
    optimization_descriptor: ObjectDescriptor,
    namespace_graph_bytes: Vec<u8>,
    namespace_graph_descriptor: ObjectDescriptor,
    advisory_program_bytes: Vec<u8>,
    advisory_program_descriptor: ObjectDescriptor,
}
impl PortablePolicyOutputV1 {
    pub(crate) fn new(
        policy: Policy,
        optimization: OptimizationProfile,
        namespace_graph: &PortableNamespaceGraphV1,
        advisory_program: &PortableAdvisoryProgramV1,
    ) -> Result<Self, PolicyModelError> {
        let optimization_bytes = encode_optimization(&optimization);
        if optimization_bytes.len() > MAXIMUM_CANONICAL_OBJECT_BYTES {
            return Err(PolicyModelError::CanonicalObjectTooLarge);
        }
        let optimization_descriptor = descriptor_for_bytes(
            media_type(PortableMediaType::Optimization)?,
            &optimization_bytes,
        );
        let policy_bytes = encode_policy(&policy);
        if policy_bytes.len() > MAXIMUM_CANONICAL_OBJECT_BYTES {
            return Err(PolicyModelError::CanonicalObjectTooLarge);
        }
        let policy_descriptor =
            descriptor_for_bytes(media_type(PortableMediaType::Policy)?, &policy_bytes);
        Ok(Self {
            policy,
            policy_bytes,
            policy_descriptor,
            optimization,
            optimization_bytes,
            optimization_descriptor,
            namespace_graph_bytes: bounded_clone(namespace_graph.canonical_bytes())?,
            namespace_graph_descriptor: namespace_graph.descriptor().clone(),
            advisory_program_bytes: bounded_clone(advisory_program.canonical_bytes())?,
            advisory_program_descriptor: advisory_program.descriptor().clone(),
        })
    }
    /// Returns the core policy.
    #[must_use]
    pub const fn policy(&self) -> &Policy {
        &self.policy
    }
    /// Returns canonical policy CBOR.
    #[must_use]
    pub fn policy_bytes(&self) -> &[u8] {
        &self.policy_bytes
    }
    /// Returns its registered descriptor.
    #[must_use]
    pub const fn policy_descriptor(&self) -> &ObjectDescriptor {
        &self.policy_descriptor
    }
    /// Returns the core optimization profile.
    #[must_use]
    pub const fn optimization(&self) -> &OptimizationProfile {
        &self.optimization
    }
    /// Returns canonical optimization CBOR.
    #[must_use]
    pub fn optimization_bytes(&self) -> &[u8] {
        &self.optimization_bytes
    }
    /// Returns its registered descriptor.
    #[must_use]
    pub const fn optimization_descriptor(&self) -> &ObjectDescriptor {
        &self.optimization_descriptor
    }
    /// Returns exact portable namespace-graph bytes required with the policy.
    #[must_use]
    pub fn namespace_graph_bytes(&self) -> &[u8] {
        &self.namespace_graph_bytes
    }
    /// Returns the inseparable namespace-graph descriptor.
    #[must_use]
    pub const fn namespace_graph_descriptor(&self) -> &ObjectDescriptor {
        &self.namespace_graph_descriptor
    }
    /// Returns exact normative advisory-selection bytes.
    #[must_use]
    pub fn advisory_program_bytes(&self) -> &[u8] {
        &self.advisory_program_bytes
    }
    /// Returns the advisory-selection descriptor preserving priority semantics.
    #[must_use]
    pub const fn advisory_program_descriptor(&self) -> &ObjectDescriptor {
        &self.advisory_program_descriptor
    }
}

/// Stores an inert candidate explicitly lacking verified ancestry authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledPolicyCandidateV1 {
    status: CandidateAuthorityV1,
    commitment: CompiledPolicyCommitmentV1,
    authority: AuthorityPlanV1,
    namespace: NamespacePlanV1,
    hard: HardResourcePlanV1,
    advisory: AdvisoryPlanV1,
    portable: PortablePolicyOutputV1,
    explanation: PlanExplanationV1,
}
impl CompiledPolicyCandidateV1 {
    pub(crate) fn new(
        authority: AuthorityPlanV1,
        namespace: NamespacePlanV1,
        hard: HardResourcePlanV1,
        advisory: AdvisoryPlanV1,
        portable: PortablePolicyOutputV1,
        explanation: PlanExplanationV1,
    ) -> Result<Self, PolicyModelError> {
        let commitment = CompiledPolicyCommitmentV1::new(digest(
            b"aos.sandbox.compiled-policy-candidate.v2",
            &(
                authority.commitment(),
                namespace.commitment(),
                hard.commitment(),
                advisory.commitment(),
                portable.policy_descriptor(),
                portable.optimization_descriptor(),
                portable.namespace_graph_descriptor(),
                portable.advisory_program_descriptor(),
                explanation.commitment(),
            ),
        )?);
        Ok(Self {
            status: CandidateAuthorityV1::NonAuthoritativeAncestry,
            commitment,
            authority,
            namespace,
            hard,
            advisory,
            portable,
            explanation,
        })
    }
    /// Returns the nonauthoritative status.
    #[must_use]
    pub const fn authority_status(&self) -> CandidateAuthorityV1 {
        self.status
    }
    /// Returns the candidate commitment.
    #[must_use]
    pub const fn commitment(&self) -> CompiledPolicyCommitmentV1 {
        self.commitment
    }
    /// Returns effective authority.
    #[must_use]
    pub const fn authority(&self) -> &AuthorityPlanV1 {
        &self.authority
    }
    /// Returns the namespace plan.
    #[must_use]
    pub const fn namespace(&self) -> &NamespacePlanV1 {
        &self.namespace
    }
    /// Returns hard resources.
    #[must_use]
    pub const fn hard_resources(&self) -> &HardResourcePlanV1 {
        &self.hard
    }
    /// Returns advisory decisions.
    #[must_use]
    pub const fn advisory(&self) -> &AdvisoryPlanV1 {
        &self.advisory
    }
    /// Returns portable output.
    #[must_use]
    pub const fn portable(&self) -> &PortablePolicyOutputV1 {
        &self.portable
    }
    /// Returns complete explanation.
    #[must_use]
    pub const fn explanation(&self) -> &PlanExplanationV1 {
        &self.explanation
    }
}

/// Reports malformed, unbounded, or noncanonical compiler models.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PolicyModelError {
    /// A set is not strictly ordered and unique.
    #[error("set-valued compiler input is not canonical")]
    SetNotCanonical,
    /// One layer has too many grants.
    #[error("policy layer exceeds 1024 grants")]
    TooManyGrants,
    /// One grant identity repeats.
    #[error("grant identity repeats within a layer")]
    DuplicateGrantIdentity,
    /// Equivalent authority repeats under another ID.
    #[error("semantic grant repeats within a layer")]
    DuplicateSemanticGrant,
    /// A selector has no safe base-v1 containment lattice.
    #[error("profile selector is unsafe in base-v1 authority")]
    UnsafeSelector,
    /// A sentinel identity was supplied where exact identity is required.
    #[error("sentinel identity is not valid compiler input")]
    AmbiguousIdentity,
    /// Namespace rules exceed their layer bound.
    #[error("policy layer exceeds 1024 namespace rules")]
    TooManyNamespaceRules,
    /// One attachment destination is assigned more than once.
    #[error("namespace attachment destination is not unique")]
    DuplicateNamespaceDestination,
    /// Advisory rules exceed their layer bound.
    #[error("policy layer exceeds 1024 advisory rules")]
    TooManyAdvisoryRules,
    /// Advisory tie remains ambiguous.
    #[error("advisory rules remain ambiguous after specificity and priority")]
    AmbiguousAdvisoryRule,
    /// Frozen layer bytes exceed 8 MiB.
    #[error("frozen policy layer exceeds 8 MiB")]
    PolicyLayerTooLarge,
    /// Layer normalization exceeds its fixed work budget.
    #[error("policy layer exceeds its normalization work budget")]
    PolicyLayerWorkExceeded,
    /// Ancestry exceeds 64 entries.
    #[error("policy ancestry exceeds 64 entries")]
    TooManyAncestors,
    /// An ancestor repeats.
    #[error("policy ancestry repeats an identity")]
    DuplicateAncestor,
    /// A compiler limit is zero.
    #[error("compiler limits must be nonzero")]
    InvalidCompilerLimits,
    /// Total input exceeds the compiler rule cap.
    #[error("compiler input exceeds the total rule cap")]
    CompilerInputTooLarge,
    /// Complete stage output exceeds its quota.
    #[error("complete stage explanation exceeds its quota")]
    ExplanationTooLarge,
    /// Explanation stages are incomplete or reordered.
    #[error("explanation stages are incomplete or reordered")]
    IncompleteExplanation,
    /// Internal deterministic encoding failed.
    #[error("normalized semantics could not be encoded")]
    CanonicalEncoding,
    /// A cache-domain class and target binding disagree.
    #[error("cache disclosure domain has an invalid target binding")]
    InvalidCacheDomainBinding,
    /// The cache-domain authority rejected exact binding bytes.
    #[error("cache disclosure domain authentication failed")]
    CacheDomainAuthenticationFailed,
    /// The sandbox-to-project authority rejected exact relationship bytes.
    #[error("sandbox-to-project relationship authentication failed")]
    SandboxProjectAuthenticationFailed,
    /// The authenticated relationship and branded project input disagree.
    #[error("sandbox-to-project relationship does not match project policy input")]
    SandboxProjectMismatch,
    /// Canonical object bytes exceed their allocation cap.
    #[error("canonical object exceeds its byte cap")]
    CanonicalObjectTooLarge,
    /// A registered media type was unexpectedly rejected.
    #[error("registered media type was rejected")]
    RegisteredMediaType,
}

fn preflight_layer(
    grants: &[Grant],
    resources: &HardResourceProfileV1,
    namespace_rules: &[NamespaceRuleV1],
    advisory_actions: &[AdvisoryActionV1],
    cache_domain: &CacheDomainInputV1,
    revocation: RevocationInputV1,
) -> Result<(), PolicyModelError> {
    // Counting the complete serializer stream charges selector and path bytes
    // before any canonical ordering keys or frozen-byte vectors are allocated.
    let value = (
        grants,
        resources,
        namespace_rules,
        advisory_actions,
        cache_domain,
        revocation,
    );
    let payload_bytes = canonical_payload_size(&value).map_err(|error| match error {
        PolicyModelError::CanonicalObjectTooLarge => PolicyModelError::PolicyLayerTooLarge,
        other => other,
    })?;
    if payload_bytes > MAXIMUM_POLICY_LAYER_BYTES {
        return Err(PolicyModelError::PolicyLayerTooLarge);
    }
    let edges = namespace_rules.iter().try_fold(0_u64, |total, rule| {
        let count = match rule {
            NamespaceRuleV1::Compose(node) => u64::try_from(node.inputs().len())
                .map_err(|_| PolicyModelError::PolicyLayerWorkExceeded)?,
            _ => 0,
        };
        total
            .checked_add(count)
            .ok_or(PolicyModelError::PolicyLayerWorkExceeded)
    })?;
    let item_work = grants
        .len()
        .checked_add(namespace_rules.len())
        .and_then(|value| value.checked_add(advisory_actions.len()))
        .and_then(|value| value.checked_add(resources.portable().len()))
        .and_then(|value| value.checked_add(resources.accounting().len()))
        .ok_or(PolicyModelError::PolicyLayerWorkExceeded)?;
    // Eight byte-visits cover preflight, both fixed-key digest passes for
    // grant/advisory entries, normalized layer encoding, and later freezing.
    let payload_work = u64::try_from(payload_bytes)
        .ok()
        .and_then(|bytes| bytes.checked_mul(8))
        .ok_or(PolicyModelError::PolicyLayerWorkExceeded)?;
    let work = u64::try_from(item_work)
        .ok()
        .and_then(|items| items.checked_add(edges))
        .and_then(|items| items.checked_add(payload_work))
        .ok_or(PolicyModelError::PolicyLayerWorkExceeded)?;
    if work > MAXIMUM_POLICY_LAYER_WORK_UNITS {
        return Err(PolicyModelError::PolicyLayerWorkExceeded);
    }
    Ok(())
}

pub(crate) fn canonical_bytes<T: Serialize>(
    domain: &'static [u8],
    value: &T,
) -> Result<Vec<u8>, PolicyModelError> {
    let mut writer = BoundedCanonicalWriter::new(MAXIMUM_CANONICAL_OBJECT_BYTES);
    serde_json::to_writer(&mut writer, value).map_err(|_| {
        if writer.exceeded {
            PolicyModelError::CanonicalObjectTooLarge
        } else {
            PolicyModelError::CanonicalEncoding
        }
    })?;
    let payload = writer.bytes;
    let capacity = domain
        .len()
        .checked_add(payload.len())
        .and_then(|length| length.checked_add(16))
        .ok_or(PolicyModelError::CanonicalObjectTooLarge)?;
    if capacity > MAXIMUM_CANONICAL_OBJECT_BYTES {
        return Err(PolicyModelError::CanonicalObjectTooLarge);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| PolicyModelError::CanonicalObjectTooLarge)?;
    bytes.extend_from_slice(
        &u64::try_from(domain.len())
            .map_err(|_| PolicyModelError::CanonicalObjectTooLarge)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(
        &u64::try_from(payload.len())
            .map_err(|_| PolicyModelError::CanonicalObjectTooLarge)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

fn canonical_payload_size<T: Serialize>(value: &T) -> Result<usize, PolicyModelError> {
    let mut writer = CountingCanonicalWriter::new(MAXIMUM_CANONICAL_OBJECT_BYTES);
    serde_json::to_writer(&mut writer, value).map_err(|_| {
        if writer.exceeded {
            PolicyModelError::CanonicalObjectTooLarge
        } else {
            PolicyModelError::CanonicalEncoding
        }
    })?;
    Ok(writer.length)
}

struct CountingCanonicalWriter {
    length: usize,
    maximum: usize,
    exceeded: bool,
}
impl CountingCanonicalWriter {
    const fn new(maximum: usize) -> Self {
        Self {
            length: 0,
            maximum,
            exceeded: false,
        }
    }
}
impl Write for CountingCanonicalWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = self
            .length
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("canonical byte count overflow"))?;
        if length > self.maximum {
            self.exceeded = true;
            return Err(io::Error::other("canonical byte cap exceeded"));
        }
        self.length = length;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct BoundedCanonicalWriter {
    bytes: Vec<u8>,
    maximum: usize,
    exceeded: bool,
}
impl BoundedCanonicalWriter {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
            exceeded: false,
        }
    }
}
impl Write for BoundedCanonicalWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("canonical byte count overflow"))?;
        if length > self.maximum {
            self.exceeded = true;
            return Err(io::Error::other("canonical byte cap exceeded"));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(|_| io::Error::other("canonical allocation failed"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(crate) fn digest<T: Serialize>(
    domain: &'static [u8],
    value: &T,
) -> Result<ObjectDigest, PolicyModelError> {
    let payload_length = canonical_payload_size(value)?;
    let total_length = domain
        .len()
        .checked_add(payload_length)
        .and_then(|length| length.checked_add(16))
        .ok_or(PolicyModelError::CanonicalObjectTooLarge)?;
    if total_length > MAXIMUM_CANONICAL_OBJECT_BYTES {
        return Err(PolicyModelError::CanonicalObjectTooLarge);
    }

    let mut hasher = Sha256::new();
    hasher.update(
        u64::try_from(domain.len())
            .map_err(|_| PolicyModelError::CanonicalObjectTooLarge)?
            .to_be_bytes(),
    );
    hasher.update(domain);
    hasher.update(
        u64::try_from(payload_length)
            .map_err(|_| PolicyModelError::CanonicalObjectTooLarge)?
            .to_be_bytes(),
    );
    serde_json::to_writer(DigestCanonicalWriter(&mut hasher), value)
        .map_err(|_| PolicyModelError::CanonicalEncoding)?;
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

struct DigestCanonicalWriter<'a>(&'a mut Sha256);
impl Write for DigestCanonicalWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn media_type(kind: PortableMediaType) -> Result<MediaType, PolicyModelError> {
    MediaType::new(kind.as_str()).map_err(|_| PolicyModelError::RegisteredMediaType)
}
fn bounded_clone(bytes: &[u8]) -> Result<Vec<u8>, PolicyModelError> {
    if bytes.len() > MAXIMUM_CANONICAL_OBJECT_BYTES {
        return Err(PolicyModelError::CanonicalObjectTooLarge);
    }
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|_| PolicyModelError::CanonicalObjectTooLarge)?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}
fn increasing<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}
