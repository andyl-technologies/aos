//! Closed namespace registry, ceiling resolution, and bounded canonical DAGs.
//!
//! The retained portable graph is encoded as:
//!
//! ```text
//! u64be(domain-length) || "aos.sandbox.portable-namespace-graph.v1" ||
//! u64be(payload-length) || canonical-json([V1, ordered-rules])
//! ```

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_core::format::descriptor_for_bytes;
use aos_sandbox_core::model::{PolicyViewAction, ViewMutation};
use aos_sandbox_core::{
    AttachmentSlotId, FeatureRef, MediaType, ObjectDescriptor, Operation, OperationSet,
    PortableMediaType, RelativePath, ResourceId, ResourceKind, Selector,
    validate_required_features,
};
use serde::Serialize;

use super::authority::AuthorityPlanV1;
use super::model::{
    ExplanationDecisionV1, ExplanationEntryV1, ExplanationReasonV1, ExplanationStageV1,
    InputSourceV1, NamespaceBackendFeatureV1, NamespacePlanCommitmentV1, PolicyCompilerInputV1,
    PolicyModelError, RedactedSubjectV1, canonical_bytes, digest,
};

/// Identifies the closed semantics of a logical source.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum NamespaceSourceClassV1 {
    /// Immutable portable content.
    Immutable,
    /// Generation-fenced live export.
    Live,
    /// Private writable delta.
    PrivateDelta,
    /// Mediated service.
    Service,
}

/// Selects one closed registered metadata-presentation semantic.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum NamespacePresentationFeatureV1 {
    /// Preserves portable POSIX ACL metadata.
    PosixAcl,
    /// Allows explicitly authorized absolute symlink targets.
    AbsoluteSymlink,
    /// Allows explicitly authorized parent-escaping symlink targets.
    ParentEscapeSymlink,
}

/// Selects explicit ordinary-view execution semantics.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ViewExecutionV1 {
    /// Commits to denying execution through the included view.
    NoExecute,
    /// Allows execution only after deriving exact `Execute` authority.
    AllowExecute,
}
impl Default for ViewExecutionV1 {
    fn default() -> Self {
        Self::NoExecute
    }
}

/// Classifies whether source verification permits executable presentation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum NamespaceExecutionClassV1 {
    /// Treats all source content as non-executable data.
    DataOnly,
    /// Proves immutable package or tool content under source-catalog policy.
    VerifiedPackageOrTool,
}

/// Verifies exact immutable package-or-tool source classification.
pub trait ExecutableSourceVerifierV1 {
    /// Verifies the descriptor and canonical source-classification bytes.
    fn verify(
        &self,
        handle: ResourceId,
        selector: &Selector,
        descriptor: &ObjectDescriptor,
        canonical_bytes: &[u8],
    ) -> bool;
}

/// Carries an externally authenticated executable package-or-tool source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthenticatedExecutableSourceV1 {
    handle: ResourceId,
    selector: Selector,
    descriptor: ObjectDescriptor,
}
impl AuthenticatedExecutableSourceV1 {
    /// Authenticates one exact immutable-tree source as a package or tool.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceModelError`] for a sentinel/non-tree source,
    /// encoding failure, or rejected external authentication.
    pub fn authenticate(
        handle: ResourceId,
        selector: Selector,
        verifier: &impl ExecutableSourceVerifierV1,
    ) -> Result<Self, NamespaceModelError> {
        if handle.as_bytes() == &[0; 16]
            || !matches!(&selector, Selector::Tree { tree } if tree.digest().as_bytes() != &[0; 32])
        {
            return Err(NamespaceModelError::InvalidExecutableSource);
        }
        let bytes = canonical_bytes(
            b"aos.sandbox.executable-source-classification.v1",
            &(
                handle,
                &selector,
                NamespaceExecutionClassV1::VerifiedPackageOrTool,
            ),
        )
        .map_err(NamespaceModelError::Model)?;
        let media = MediaType::new(PortableMediaType::Content.as_str())
            .map_err(|_| NamespaceModelError::InvalidExecutableSource)?;
        let descriptor = descriptor_for_bytes(media, &bytes);
        if !verifier.verify(handle, &selector, &descriptor, &bytes) {
            return Err(NamespaceModelError::ExecutableSourceAuthenticationFailed);
        }
        Ok(Self {
            handle,
            selector,
            descriptor,
        })
    }
    /// Returns the authenticated source handle.
    #[must_use]
    pub const fn handle(&self) -> ResourceId {
        self.handle
    }
    /// Returns the authenticated immutable-tree selector.
    #[must_use]
    pub const fn selector(&self) -> &Selector {
        &self.selector
    }
    /// Returns the exact external classification descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.descriptor
    }
}
impl NamespacePresentationFeatureV1 {
    fn feature(self) -> Result<FeatureRef, NamespaceCompilationError> {
        let namespace = match self {
            Self::PosixAcl => "aos.sandbox.metadata.posix-acl",
            Self::AbsoluteSymlink => "aos.sandbox.symlink.absolute",
            Self::ParentEscapeSymlink => "aos.sandbox.symlink.parent-escape",
        };
        FeatureRef::new(namespace, 1, 0).map_err(|_| NamespaceCompilationError::UnknownFeature)
    }
}

/// Declares a logical source without caller-chosen operations or features.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LogicalSourceV1 {
    handle: ResourceId,
    resource_kind: ResourceKind,
    selector: Selector,
    class: NamespaceSourceClassV1,
    execution_class: NamespaceExecutionClassV1,
    executable_source: Option<AuthenticatedExecutableSourceV1>,
}
impl LogicalSourceV1 {
    /// Constructs one closed logical source.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceModelError`] when class/kind disagree, a selector is
    /// unsafe, or executable evidence does not exactly match this source.
    pub fn new(
        handle: ResourceId,
        resource_kind: ResourceKind,
        selector: Selector,
        class: NamespaceSourceClassV1,
        executable_source: Option<AuthenticatedExecutableSourceV1>,
    ) -> Result<Self, NamespaceModelError> {
        if handle.as_bytes() == &[0; 16] {
            return Err(NamespaceModelError::AmbiguousIdentity);
        }
        let compatible = matches!(
            (class, resource_kind),
            (NamespaceSourceClassV1::Immutable, ResourceKind::Tree)
                | (NamespaceSourceClassV1::Live, ResourceKind::LiveExport)
                | (
                    NamespaceSourceClassV1::PrivateDelta,
                    ResourceKind::PrivateDelta
                )
                | (NamespaceSourceClassV1::Service, ResourceKind::IpcService)
        );
        if !compatible {
            return Err(NamespaceModelError::SourceKindMismatch);
        }
        if executable_source.as_ref().is_some_and(|authenticated| {
            class != NamespaceSourceClassV1::Immutable
                || resource_kind != ResourceKind::Tree
                || authenticated.handle() != handle
                || authenticated.selector() != &selector
        }) {
            return Err(NamespaceModelError::InvalidExecutionClass);
        }
        let execution_class = if executable_source.is_some() {
            NamespaceExecutionClassV1::VerifiedPackageOrTool
        } else {
            NamespaceExecutionClassV1::DataOnly
        };
        match &selector {
            Selector::Profile { .. } => return Err(NamespaceModelError::UnsafeSelector),
            Selector::Resource { resource } if resource.as_bytes() == &[0; 16] => {
                return Err(NamespaceModelError::AmbiguousIdentity);
            }
            Selector::Path { export, .. } if export.as_bytes() == &[0; 16] => {
                return Err(NamespaceModelError::AmbiguousIdentity);
            }
            Selector::Tree { tree } if tree.digest().as_bytes() == &[0; 32] => {
                return Err(NamespaceModelError::AmbiguousIdentity);
            }
            _ => {}
        }
        Ok(Self {
            handle,
            resource_kind,
            selector,
            class,
            execution_class,
            executable_source,
        })
    }
    /// Returns the logical handle.
    #[must_use]
    pub const fn handle(&self) -> ResourceId {
        self.handle
    }
    /// Returns the capability resource kind.
    #[must_use]
    pub const fn resource_kind(&self) -> ResourceKind {
        self.resource_kind
    }
    /// Returns the structural selector.
    #[must_use]
    pub const fn selector(&self) -> &Selector {
        &self.selector
    }
    /// Returns the closed source class.
    #[must_use]
    pub const fn class(&self) -> NamespaceSourceClassV1 {
        self.class
    }
    /// Returns the closed executable-content verification class.
    #[must_use]
    pub const fn execution_class(&self) -> NamespaceExecutionClassV1 {
        self.execution_class
    }
    /// Returns authenticated executable-source evidence when present.
    #[must_use]
    pub const fn executable_source(&self) -> Option<&AuthenticatedExecutableSourceV1> {
        self.executable_source.as_ref()
    }
}

/// Defines a pure logical composition output and canonical dependency set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NamespaceCompositionV1 {
    output: ResourceId,
    inputs: Vec<ResourceId>,
}
impl NamespaceCompositionV1 {
    /// Constructs one bounded canonical composition.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceModelError`] for empty, oversized, unordered, or duplicate inputs.
    pub fn new(output: ResourceId, inputs: Vec<ResourceId>) -> Result<Self, NamespaceModelError> {
        if output.as_bytes() == &[0; 16]
            || inputs.iter().any(|input| input.as_bytes() == &[0; 16])
            || inputs.is_empty()
            || inputs.len() > 256
            || !inputs.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(NamespaceModelError::InvalidComposition);
        }
        Ok(Self { output, inputs })
    }
    /// Returns the output handle.
    #[must_use]
    pub const fn output(&self) -> ResourceId {
        self.output
    }
    /// Returns dependency handles.
    #[must_use]
    pub fn inputs(&self) -> &[ResourceId] {
        &self.inputs
    }
}

/// Stores one complete portable namespace rule.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum NamespaceRuleV1 {
    /// Declares a source handle.
    Source(LogicalSourceV1),
    /// Declares a logical composition.
    Compose(NamespaceCompositionV1),
    /// Includes a source subtree.
    Include {
        /// Logical source handle.
        source: ResourceId,
        /// View-relative prefix.
        prefix: RelativePath,
        /// Explicit executable or noexec semantics.
        execution: ViewExecutionV1,
    },
    /// Excludes a presented subtree.
    Exclude {
        /// View-relative prefix.
        prefix: RelativePath,
    },
    /// Attaches a source at an authenticated destination.
    Attach {
        /// Logical source handle.
        source: ResourceId,
        /// Destination slot.
        destination: AttachmentSlotId,
        /// One of all five portable mutation modes.
        mode: ViewMutation,
        /// Explicit executable or noexec semantics, defaulting to noexec.
        execution: ViewExecutionV1,
    },
    /// Applies a registered metadata profile.
    Present {
        /// View-relative prefix.
        prefix: RelativePath,
        /// Closed registered presentation semantic.
        presentation: NamespacePresentationFeatureV1,
    },
}

/// Binds one destination slot to its authenticated capability resource.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NamespaceDestinationV1 {
    slot: AttachmentSlotId,
    resource: ResourceId,
}
impl NamespaceDestinationV1 {
    /// Constructs one catalog statement.
    #[must_use]
    pub const fn new(slot: AttachmentSlotId, resource: ResourceId) -> Self {
        Self { slot, resource }
    }
    /// Returns the slot.
    #[must_use]
    pub const fn slot(self) -> AttachmentSlotId {
        self.slot
    }
    /// Returns its capability resource.
    #[must_use]
    pub const fn resource(self) -> ResourceId {
        self.resource
    }
}

/// Verifies a destination catalog through an external authority.
pub trait NamespaceCatalogVerifierV1 {
    /// Verifies exact catalog bytes and descriptor.
    fn verify(&self, descriptor: &ObjectDescriptor, canonical_bytes: &[u8]) -> bool;
}

/// Carries destination bindings accepted by an explicit verifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthenticatedNamespaceCatalogV1 {
    descriptor: ObjectDescriptor,
    destinations: Vec<NamespaceDestinationV1>,
}
impl AuthenticatedNamespaceCatalogV1 {
    /// Canonicalizes and authenticates destination relations.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceCatalogError`] for invalid order, bounds, sentinels, or authentication.
    pub fn authenticate(
        destinations: Vec<NamespaceDestinationV1>,
        verifier: &impl NamespaceCatalogVerifierV1,
    ) -> Result<Self, NamespaceCatalogError> {
        if destinations.len() > 4_096
            || !destinations
                .windows(2)
                .all(|pair| pair[0].slot < pair[1].slot)
            || destinations.iter().any(|item| {
                item.slot.as_bytes() == &[0; 16] || item.resource.as_bytes() == &[0; 16]
            })
        {
            return Err(NamespaceCatalogError::InvalidCatalog);
        }
        let bytes = canonical_bytes(
            b"aos.sandbox.namespace-destination-catalog.v2",
            &destinations,
        )
        .map_err(|_| NamespaceCatalogError::InvalidCatalog)?;
        let media = MediaType::new(PortableMediaType::Content.as_str())
            .map_err(|_| NamespaceCatalogError::InvalidCatalog)?;
        let descriptor = descriptor_for_bytes(media, &bytes);
        if !verifier.verify(&descriptor, &bytes) {
            return Err(NamespaceCatalogError::AuthenticationFailed);
        }
        Ok(Self {
            descriptor,
            destinations,
        })
    }
    /// Returns the authenticated descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.descriptor
    }
    /// Returns canonical authenticated destination bindings.
    #[must_use]
    pub fn entries(&self) -> &[NamespaceDestinationV1] {
        &self.destinations
    }
    fn resolve(&self, slot: AttachmentSlotId) -> Option<ResourceId> {
        self.destinations
            .binary_search_by_key(&slot, |entry| entry.slot)
            .ok()
            .map(|index| self.destinations[index].resource)
    }
}

/// Reports invalid or unauthenticated destination catalogs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NamespaceCatalogError {
    /// Shape, order, bound, or sentinels are invalid.
    #[error("namespace destination catalog is invalid")]
    InvalidCatalog,
    /// The configured authority rejected exact bytes.
    #[error("namespace destination catalog authentication failed")]
    AuthenticationFailed,
}

/// Stores a canonical DAG, portable actions, and derived authority/features.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NamespacePlanV1 {
    commitment: NamespacePlanCommitmentV1,
    rules: Vec<NamespaceRuleV1>,
    core_actions: Vec<PolicyViewAction>,
    required_features: Vec<FeatureRef>,
    destination_catalog: ObjectDescriptor,
    graph: PortableNamespaceGraphV1,
    reachable_sources: Vec<ResourceId>,
}

/// Names the exact portable namespace-graph schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum NamespaceGraphSchemaV1 {
    /// Canonical source, composition, and presentation graph version 1.
    V1,
}

/// Stores the exact portable-evaluable source graph retained beside core policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PortableNamespaceGraphV1 {
    schema: NamespaceGraphSchemaV1,
    rules: Vec<NamespaceRuleV1>,
    descriptor: ObjectDescriptor,
    bytes: Vec<u8>,
}
impl PortableNamespaceGraphV1 {
    fn new(rules: Vec<NamespaceRuleV1>) -> Result<Self, PolicyModelError> {
        let schema = NamespaceGraphSchemaV1::V1;
        let bytes = canonical_bytes(
            b"aos.sandbox.portable-namespace-graph.v1",
            &(schema, &rules),
        )?;
        let media = MediaType::new(PortableMediaType::Content.as_str())
            .map_err(|_| PolicyModelError::RegisteredMediaType)?;
        let descriptor = descriptor_for_bytes(media, &bytes);
        Ok(Self {
            schema,
            rules,
            descriptor,
            bytes,
        })
    }
    /// Returns the closed graph schema.
    #[must_use]
    pub const fn schema(&self) -> NamespaceGraphSchemaV1 {
        self.schema
    }
    /// Returns canonical source, composition, and presentation rules.
    #[must_use]
    pub fn rules(&self) -> &[NamespaceRuleV1] {
        &self.rules
    }
    /// Returns the graph descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.descriptor
    }
    /// Returns exact canonical graph bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl NamespacePlanV1 {
    /// Returns the commitment.
    #[must_use]
    pub const fn commitment(&self) -> NamespacePlanCommitmentV1 {
        self.commitment
    }
    /// Returns canonical definitions followed by semantic presentation rules.
    #[must_use]
    pub fn rules(&self) -> &[NamespaceRuleV1] {
        &self.rules
    }
    /// Returns totally lowered portable actions.
    #[must_use]
    pub fn core_actions(&self) -> &[PolicyViewAction] {
        &self.core_actions
    }
    /// Returns derived registered feature requirements.
    #[must_use]
    pub fn required_features(&self) -> &[FeatureRef] {
        &self.required_features
    }
    /// Returns the authenticated destination catalog descriptor.
    #[must_use]
    pub const fn destination_catalog(&self) -> &ObjectDescriptor {
        &self.destination_catalog
    }
    /// Returns the exact portable source-graph object.
    #[must_use]
    pub const fn graph(&self) -> &PortableNamespaceGraphV1 {
        &self.graph
    }
    /// Reports whether a source is reachable from the resulting view.
    #[must_use]
    pub fn source_is_reachable(&self, source: ResourceId) -> bool {
        self.reachable_sources.binary_search(&source).is_ok()
    }
    pub(crate) fn source(&self, handle: ResourceId) -> Option<&LogicalSourceV1> {
        self.rules.iter().find_map(|rule| match rule {
            NamespaceRuleV1::Source(source) if source.handle == handle => Some(source),
            _ => None,
        })
    }
}

pub(crate) fn validate_namespace_rule_sequence(
    rules: Vec<NamespaceRuleV1>,
) -> Result<Vec<NamespaceRuleV1>, PolicyModelError> {
    let definitions = rules.iter().filter_map(definition).collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    if definitions.iter().any(|handle| !seen.insert(*handle)) {
        return Err(PolicyModelError::TooManyNamespaceRules);
    }
    let destinations = rules.iter().filter_map(|rule| match rule {
        NamespaceRuleV1::Attach { destination, .. } => Some(*destination),
        _ => None,
    });
    let mut seen_destinations = BTreeSet::new();
    if destinations
        .into_iter()
        .any(|destination| !seen_destinations.insert(destination))
    {
        return Err(PolicyModelError::DuplicateNamespaceDestination);
    }
    Ok(rules)
}

pub(crate) fn compile_namespace(
    input: &PolicyCompilerInputV1,
    authority: &AuthorityPlanV1,
) -> Result<(NamespacePlanV1, Vec<ExplanationEntryV1>), NamespaceCompilationError> {
    let requested = input.request().layer().namespace_rules();
    for rule in requested {
        for (_, ceiling, _) in input.ceiling_layers() {
            if !ceiling_covers(ceiling.namespace_rules(), rule) {
                return Err(NamespaceCompilationError::CeilingDenied);
            }
        }
    }
    let analysis = canonical_dag(requested, input.limits().dag_depth())?;
    let ordered = analysis.ordered;
    let requirements = derive_source_requirements(&ordered)?;
    let mut features = BTreeSet::new();
    let reachable_sources = reachable_leaf_sources(&analysis.dependencies, &ordered)?;
    let mut core_actions = Vec::new();
    let mut explanation = Vec::new();
    for rule in &ordered {
        match rule {
            NamespaceRuleV1::Source(source) => {
                let operations = match requirements.get(&source.handle()) {
                    Some(operations) => *operations,
                    None => OperationSet::one(Operation::Discover),
                };
                if !authority.admits(source.resource_kind(), operations, source.selector()) {
                    return Err(NamespaceCompilationError::UnauthorizedSource);
                }
                let backend = backend_for_source(source.class());
                if input.backend().namespace().binary_search(&backend).is_err() {
                    return Err(NamespaceCompilationError::BackendUnavailable);
                }
                features.insert(namespace_feature(backend)?);
                explanation.push(explain(
                    rule,
                    ExplanationReasonV1::NamespaceSource,
                    InputSourceV1::Request,
                )?);
            }
            NamespaceRuleV1::Compose(_) => explanation.push(explain(
                rule,
                ExplanationReasonV1::NamespaceComposition,
                InputSourceV1::Request,
            )?),
            NamespaceRuleV1::Include {
                source,
                prefix,
                execution,
            } => {
                ensure_handle(&analysis.dependencies, *source)?;
                let classes = analysis
                    .leaf_classes
                    .get(source)
                    .ok_or(NamespaceCompilationError::UnknownHandle)?;
                if classes.contains(&NamespaceSourceClassV1::Service) {
                    return Err(NamespaceCompilationError::ServiceInclude);
                }
                ensure_execution_class(&analysis.leaf_execution_classes, *source, *execution)?;
                if *execution == ViewExecutionV1::NoExecute {
                    let backend = NamespaceBackendFeatureV1::NoExecute;
                    if input.backend().namespace().binary_search(&backend).is_err() {
                        return Err(NamespaceCompilationError::BackendUnavailable);
                    }
                    // Base v1 has no registered FeatureRef for noexec. The
                    // typed backend proof and inseparable graph object carry
                    // this hard denial without mislabelling another feature.
                }
                core_actions.push(PolicyViewAction::Include {
                    source: *source,
                    prefix: prefix.clone(),
                });
                explanation.push(explain(
                    rule,
                    if *execution == ViewExecutionV1::NoExecute {
                        ExplanationReasonV1::NamespaceNoExecute
                    } else {
                        ExplanationReasonV1::NamespaceExecute
                    },
                    InputSourceV1::Request,
                )?);
            }
            NamespaceRuleV1::Exclude { prefix } => {
                core_actions.push(PolicyViewAction::Exclude {
                    prefix: prefix.clone(),
                });
                explanation.push(explain(
                    rule,
                    ExplanationReasonV1::NamespacePresentation,
                    InputSourceV1::Request,
                )?);
            }
            NamespaceRuleV1::Attach {
                source,
                destination,
                mode,
                execution,
            } => {
                ensure_handle(&analysis.dependencies, *source)?;
                let classes = analysis
                    .leaf_classes
                    .get(source)
                    .ok_or(NamespaceCompilationError::UnknownHandle)?;
                if classes
                    .iter()
                    .any(|class| !mode_is_compatible(*class, *mode))
                {
                    return Err(NamespaceCompilationError::IncompatibleMode);
                }
                if *mode == ViewMutation::Service && *execution == ViewExecutionV1::AllowExecute {
                    return Err(NamespaceCompilationError::ServiceExecution);
                }
                ensure_execution_class(&analysis.leaf_execution_classes, *source, *execution)?;
                if *execution == ViewExecutionV1::NoExecute
                    && input
                        .backend()
                        .namespace()
                        .binary_search(&NamespaceBackendFeatureV1::NoExecute)
                        .is_err()
                {
                    return Err(NamespaceCompilationError::BackendUnavailable);
                }
                let resource = input
                    .destinations()
                    .resolve(*destination)
                    .ok_or(NamespaceCompilationError::UnknownDestination)?;
                if !authority.admits(
                    ResourceKind::AttachmentSlot,
                    OperationSet::one(Operation::Attach),
                    &Selector::Resource { resource },
                ) {
                    return Err(NamespaceCompilationError::UnauthorizedDestination);
                }
                if let Some(backend) = backend_for_mode(*mode) {
                    if input.backend().namespace().binary_search(&backend).is_err() {
                        return Err(NamespaceCompilationError::BackendUnavailable);
                    }
                    features.insert(namespace_feature(backend)?);
                }
                core_actions.push(PolicyViewAction::Attach {
                    source: *source,
                    destination_slot: *destination,
                    mode: *mode,
                });
                explanation.push(explain(
                    rule,
                    ExplanationReasonV1::DestinationAuthority,
                    InputSourceV1::Catalog,
                )?);
                if *execution == ViewExecutionV1::NoExecute {
                    explanation.push(explain(
                        rule,
                        ExplanationReasonV1::NamespaceNoExecute,
                        InputSourceV1::Backend,
                    )?);
                } else {
                    explanation.push(explain(
                        rule,
                        ExplanationReasonV1::NamespaceExecute,
                        InputSourceV1::Request,
                    )?);
                }
            }
            NamespaceRuleV1::Present {
                prefix,
                presentation,
            } => {
                let feature = presentation.feature()?;
                validate_required_features(std::slice::from_ref(&feature))
                    .map_err(|_| NamespaceCompilationError::UnknownFeature)?;
                if input
                    .backend()
                    .namespace()
                    .binary_search(&NamespaceBackendFeatureV1::MetadataPresentation)
                    .is_err()
                {
                    return Err(NamespaceCompilationError::BackendUnavailable);
                }
                features.insert(feature.clone());
                core_actions.push(PolicyViewAction::Present {
                    prefix: prefix.clone(),
                    presentation_profile: feature,
                });
                explanation.push(explain(
                    rule,
                    ExplanationReasonV1::NamespacePresentation,
                    InputSourceV1::Request,
                )?);
            }
        }
    }
    let required_features = features.into_iter().collect::<Vec<_>>();
    let reachable_sources = reachable_sources.into_iter().collect::<Vec<_>>();
    let destination_catalog = input.destinations().descriptor().clone();
    let graph = PortableNamespaceGraphV1::new(ordered.clone())?;
    let commitment = NamespacePlanCommitmentV1::new(digest(
        b"aos.sandbox.namespace-plan.v2",
        &(
            &ordered,
            &core_actions,
            &required_features,
            &destination_catalog,
            graph.descriptor(),
            &reachable_sources,
        ),
    )?);
    Ok((
        NamespacePlanV1 {
            commitment,
            rules: ordered,
            core_actions,
            required_features,
            destination_catalog,
            graph,
            reachable_sources,
        },
        explanation,
    ))
}

fn definition(rule: &NamespaceRuleV1) -> Option<ResourceId> {
    match rule {
        NamespaceRuleV1::Source(source) => Some(source.handle()),
        NamespaceRuleV1::Compose(node) => Some(node.output()),
        _ => None,
    }
}
fn ceiling_covers(rules: &[NamespaceRuleV1], requested: &NamespaceRuleV1) -> bool {
    match requested {
        NamespaceRuleV1::Source(source) => rules.iter().any(|rule| matches!(rule,
            NamespaceRuleV1::Source(ceiling) if ceiling.handle() == source.handle()
                && ceiling.resource_kind() == source.resource_kind() && ceiling.class() == source.class()
                && (source.execution_class() == NamespaceExecutionClassV1::DataOnly
                    || ceiling.execution_class() == NamespaceExecutionClassV1::VerifiedPackageOrTool)
                && ceiling.selector().contains(source.selector()))),
        _ => rules.contains(requested),
    }
}
struct DagAnalysisV1 {
    ordered: Vec<NamespaceRuleV1>,
    dependencies: BTreeMap<ResourceId, Vec<ResourceId>>,
    leaf_classes: BTreeMap<ResourceId, BTreeSet<NamespaceSourceClassV1>>,
    leaf_execution_classes: BTreeMap<ResourceId, BTreeSet<NamespaceExecutionClassV1>>,
}

fn canonical_dag(
    rules: &[NamespaceRuleV1],
    maximum_depth: u16,
) -> Result<DagAnalysisV1, NamespaceCompilationError> {
    let mut definitions = BTreeMap::new();
    let mut originals = BTreeMap::new();
    for rule in rules {
        if let Some(handle) = definition(rule) {
            let dependencies = match rule {
                NamespaceRuleV1::Compose(node) => node.inputs().to_vec(),
                _ => Vec::new(),
            };
            if definitions.insert(handle, dependencies).is_some() {
                return Err(NamespaceCompilationError::DuplicateHandle);
            }
            originals.insert(handle, rule.clone());
        }
    }
    let mut dependents: BTreeMap<ResourceId, Vec<ResourceId>> = BTreeMap::new();
    let mut indegree = BTreeMap::new();
    for (handle, dependencies) in &definitions {
        indegree.insert(*handle, dependencies.len());
        for dependency in dependencies {
            if !definitions.contains_key(dependency) {
                return Err(NamespaceCompilationError::UnknownHandle);
            }
            dependents.entry(*dependency).or_default().push(*handle);
        }
    }
    let mut ready = indegree
        .iter()
        .filter_map(|(handle, count)| (*count == 0).then_some(*handle))
        .collect::<BTreeSet<_>>();
    let mut result = Vec::with_capacity(rules.len());
    let mut depth = BTreeMap::new();
    let mut leaf_classes = BTreeMap::new();
    let mut leaf_execution_classes = BTreeMap::new();
    while let Some(handle) = ready.pop_first() {
        let dependencies = definitions
            .get(&handle)
            .ok_or(NamespaceCompilationError::UnknownHandle)?;
        let prior_depth = match dependencies
            .iter()
            .filter_map(|item| depth.get(item))
            .copied()
            .max()
        {
            Some(depth) => depth,
            None => 0_u16,
        };
        let node_depth = prior_depth
            .checked_add(1)
            .ok_or(NamespaceCompilationError::DepthExceeded)?;
        if node_depth > maximum_depth {
            return Err(NamespaceCompilationError::DepthExceeded);
        }
        depth.insert(handle, node_depth);

        match originals
            .get(&handle)
            .ok_or(NamespaceCompilationError::UnknownHandle)?
        {
            NamespaceRuleV1::Source(source) => {
                leaf_classes.insert(handle, BTreeSet::from([source.class()]));
                leaf_execution_classes.insert(handle, BTreeSet::from([source.execution_class()]));
            }
            NamespaceRuleV1::Compose(_) => {
                let mut classes = BTreeSet::new();
                let mut execution_classes = BTreeSet::new();
                for dependency in dependencies {
                    classes.extend(
                        leaf_classes
                            .get(dependency)
                            .ok_or(NamespaceCompilationError::UnknownHandle)?,
                    );
                    execution_classes.extend(
                        leaf_execution_classes
                            .get(dependency)
                            .ok_or(NamespaceCompilationError::UnknownHandle)?,
                    );
                }
                leaf_classes.insert(handle, classes);
                leaf_execution_classes.insert(handle, execution_classes);
            }
            _ => return Err(NamespaceCompilationError::UnknownHandle),
        }
        result.push(
            originals
                .get(&handle)
                .ok_or(NamespaceCompilationError::UnknownHandle)?
                .clone(),
        );
        if let Some(outputs) = dependents.get(&handle) {
            for output in outputs {
                let count = indegree
                    .get_mut(output)
                    .ok_or(NamespaceCompilationError::UnknownHandle)?;
                *count = count
                    .checked_sub(1)
                    .ok_or(NamespaceCompilationError::Cycle)?;
                if *count == 0 {
                    ready.insert(*output);
                }
            }
        }
    }
    if result.len() != definitions.len() {
        return Err(NamespaceCompilationError::Cycle);
    }
    result.extend(
        rules
            .iter()
            .filter(|rule| definition(rule).is_none())
            .cloned(),
    );
    Ok(DagAnalysisV1 {
        ordered: result,
        dependencies: definitions,
        leaf_classes,
        leaf_execution_classes,
    })
}
fn derive_source_requirements(
    rules: &[NamespaceRuleV1],
) -> Result<BTreeMap<ResourceId, OperationSet>, NamespaceCompilationError> {
    let mut requirements = BTreeMap::new();
    for rule in rules {
        match rule {
            NamespaceRuleV1::Include {
                source, execution, ..
            } => {
                let mut operations = OperationSet::one(Operation::Discover)
                    .union(OperationSet::one(Operation::MetadataRead))
                    .union(OperationSet::one(Operation::ContentRead));
                if *execution == ViewExecutionV1::AllowExecute {
                    operations = operations.union(OperationSet::one(Operation::Execute));
                }
                add_requirement(&mut requirements, *source, operations);
            }
            NamespaceRuleV1::Attach {
                source,
                mode,
                execution,
                ..
            } => {
                let mut operations = operations_for_mode(*mode);
                if *execution == ViewExecutionV1::AllowExecute {
                    operations = operations.union(OperationSet::one(Operation::Execute));
                }
                add_requirement(&mut requirements, *source, operations)
            }
            _ => {}
        }
    }
    for rule in rules.iter().rev() {
        if let NamespaceRuleV1::Compose(node) = rule {
            let operations = match requirements.get(&node.output()) {
                Some(operations) => *operations,
                None => OperationSet::one(Operation::Discover),
            };
            for input in node.inputs() {
                add_requirement(&mut requirements, *input, operations);
            }
        }
    }
    for rule in rules {
        if let NamespaceRuleV1::Source(source) = rule
            && source.class() == NamespaceSourceClassV1::Live
            && requirements
                .get(&source.handle())
                .is_some_and(|set| set.contains(Operation::ContentRead))
        {
            add_requirement(
                &mut requirements,
                source.handle(),
                OperationSet::one(Operation::LiveKernelCoupledRead),
            );
        }
    }
    Ok(requirements)
}
fn add_requirement(
    map: &mut BTreeMap<ResourceId, OperationSet>,
    handle: ResourceId,
    value: OperationSet,
) {
    map.entry(handle)
        .and_modify(|current| *current = current.union(value))
        .or_insert(value);
}
fn reachable_leaf_sources(
    dependencies: &BTreeMap<ResourceId, Vec<ResourceId>>,
    rules: &[NamespaceRuleV1],
) -> Result<BTreeSet<ResourceId>, NamespaceCompilationError> {
    let mut pending = rules
        .iter()
        .filter_map(|rule| match rule {
            NamespaceRuleV1::Include { source, .. } | NamespaceRuleV1::Attach { source, .. } => {
                Some(*source)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut visited = BTreeSet::new();
    let mut leaves = BTreeSet::new();
    while let Some(handle) = pending.pop() {
        if !visited.insert(handle) {
            continue;
        }
        let inputs = dependencies
            .get(&handle)
            .ok_or(NamespaceCompilationError::UnknownHandle)?;
        if inputs.is_empty() {
            leaves.insert(handle);
        } else {
            pending.extend_from_slice(inputs);
        }
    }
    Ok(leaves)
}
fn operations_for_mode(mode: ViewMutation) -> OperationSet {
    let read = OperationSet::one(Operation::Discover)
        .union(OperationSet::one(Operation::MetadataRead))
        .union(OperationSet::one(Operation::ContentRead));
    match mode {
        ViewMutation::ReadOnly => read,
        ViewMutation::ReadWrite => read
            .union(OperationSet::one(Operation::Create))
            .union(OperationSet::one(Operation::ContentWrite))
            .union(OperationSet::one(Operation::Remove))
            .union(OperationSet::one(Operation::Rename))
            .union(OperationSet::one(Operation::Link))
            .union(OperationSet::one(Operation::MetadataWrite)),
        // Private writes are authority on the authenticated destination, not
        // accidental write authority over an immutable source.
        ViewMutation::PrivateCow => read,
        ViewMutation::AppendOnly => read
            .union(OperationSet::one(Operation::Create))
            .union(OperationSet::one(Operation::ContentWrite))
            .union(OperationSet::one(Operation::Publish)),
        ViewMutation::Service => {
            OperationSet::one(Operation::Discover).union(OperationSet::one(Operation::Attach))
        }
    }
}
fn ensure_execution_class(
    classes: &BTreeMap<ResourceId, BTreeSet<NamespaceExecutionClassV1>>,
    source: ResourceId,
    execution: ViewExecutionV1,
) -> Result<(), NamespaceCompilationError> {
    if execution == ViewExecutionV1::NoExecute {
        return Ok(());
    }
    let classes = classes
        .get(&source)
        .ok_or(NamespaceCompilationError::UnknownHandle)?;
    if classes.len() == 1 && classes.contains(&NamespaceExecutionClassV1::VerifiedPackageOrTool) {
        Ok(())
    } else {
        Err(NamespaceCompilationError::UnverifiedExecutableSource)
    }
}
fn backend_for_source(class: NamespaceSourceClassV1) -> NamespaceBackendFeatureV1 {
    match class {
        NamespaceSourceClassV1::Immutable => NamespaceBackendFeatureV1::Immutable,
        NamespaceSourceClassV1::Live => NamespaceBackendFeatureV1::LiveReadOnly,
        NamespaceSourceClassV1::PrivateDelta => NamespaceBackendFeatureV1::ReadWrite,
        NamespaceSourceClassV1::Service => NamespaceBackendFeatureV1::Service,
    }
}
fn backend_for_mode(mode: ViewMutation) -> Option<NamespaceBackendFeatureV1> {
    match mode {
        ViewMutation::ReadOnly => None,
        ViewMutation::ReadWrite => Some(NamespaceBackendFeatureV1::ReadWrite),
        ViewMutation::PrivateCow => Some(NamespaceBackendFeatureV1::PrivateCow),
        ViewMutation::AppendOnly => Some(NamespaceBackendFeatureV1::AppendOnly),
        ViewMutation::Service => Some(NamespaceBackendFeatureV1::Service),
    }
}
fn mode_is_compatible(class: NamespaceSourceClassV1, mode: ViewMutation) -> bool {
    matches!(
        (class, mode),
        (
            NamespaceSourceClassV1::Immutable,
            ViewMutation::ReadOnly | ViewMutation::PrivateCow
        ) | (
            NamespaceSourceClassV1::Live,
            ViewMutation::ReadOnly | ViewMutation::ReadWrite
        ) | (
            NamespaceSourceClassV1::PrivateDelta,
            ViewMutation::ReadOnly | ViewMutation::ReadWrite | ViewMutation::AppendOnly
        ) | (NamespaceSourceClassV1::Service, ViewMutation::Service)
    )
}
fn namespace_feature(
    backend: NamespaceBackendFeatureV1,
) -> Result<FeatureRef, NamespaceCompilationError> {
    let namespace = match backend {
        NamespaceBackendFeatureV1::Immutable => "aos.sandbox.storage.portable",
        NamespaceBackendFeatureV1::LiveReadOnly
        | NamespaceBackendFeatureV1::ReadWrite
        | NamespaceBackendFeatureV1::PrivateCow
        | NamespaceBackendFeatureV1::AppendOnly
        | NamespaceBackendFeatureV1::Service => "aos.sandbox.mount.source-acquisition",
        NamespaceBackendFeatureV1::MetadataPresentation => "aos.sandbox.metadata.posix-acl",
        NamespaceBackendFeatureV1::NoExecute => {
            return Err(NamespaceCompilationError::UnknownFeature);
        }
    };
    FeatureRef::new(namespace, 1, 0).map_err(|_| NamespaceCompilationError::UnknownFeature)
}
fn ensure_handle(
    definitions: &BTreeMap<ResourceId, Vec<ResourceId>>,
    handle: ResourceId,
) -> Result<(), NamespaceCompilationError> {
    if definitions.contains_key(&handle) {
        Ok(())
    } else {
        Err(NamespaceCompilationError::UnknownHandle)
    }
}
fn explain(
    rule: &NamespaceRuleV1,
    reason: ExplanationReasonV1,
    source: InputSourceV1,
) -> Result<ExplanationEntryV1, PolicyModelError> {
    Ok(ExplanationEntryV1::new(
        ExplanationStageV1::Namespace,
        ExplanationDecisionV1::Admitted,
        reason,
        source,
        RedactedSubjectV1::for_value(rule)?,
        Vec::new(),
    ))
}

/// Reports malformed namespace models.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NamespaceModelError {
    /// Source class and capability kind disagree.
    #[error("namespace source class and resource kind disagree")]
    SourceKindMismatch,
    /// Executable verification is asserted for a source class that cannot carry it.
    #[error("only immutable package or tool sources may be executable")]
    InvalidExecutionClass,
    /// Executable source shape or selector is invalid.
    #[error("executable source classification requires an exact immutable tree")]
    InvalidExecutableSource,
    /// The external package/tool authority rejected exact source bytes.
    #[error("executable source classification authentication failed")]
    ExecutableSourceAuthenticationFailed,
    /// Profile selectors lack a safe base-v1 lattice.
    #[error("profile selectors are not safe in base-v1 namespace authority")]
    UnsafeSelector,
    /// A source or composition uses a sentinel identity.
    #[error("sentinel identity is not valid namespace input")]
    AmbiguousIdentity,
    /// Composition inputs are invalid.
    #[error("composition must have 1..=256 canonical unique inputs")]
    InvalidComposition,
    /// Frozen executable-source encoding failed.
    #[error("executable source classification could not be encoded: {0}")]
    Model(PolicyModelError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NamespaceCompilationError {
    CeilingDenied,
    DuplicateHandle,
    UnknownHandle,
    Cycle,
    DepthExceeded,
    UnauthorizedSource,
    UnknownDestination,
    UnauthorizedDestination,
    IncompatibleMode,
    ServiceInclude,
    ServiceExecution,
    UnverifiedExecutableSource,
    BackendUnavailable,
    UnknownFeature,
    Model(PolicyModelError),
}
impl From<PolicyModelError> for NamespaceCompilationError {
    fn from(value: PolicyModelError) -> Self {
        Self::Model(value)
    }
}
