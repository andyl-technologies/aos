//! Finite source-installed providers and original inactive realization custody.
//!
//! Registration is operator configuration. Portable selections cannot install
//! authorities, and provider manifests cannot qualify their own guarantees.
//! Both the installed source inspector and ordinary behavioral admission must
//! accept each exact planned binding before native preparation starts.

use std::{collections::BTreeMap, io::Write, rc::Rc};

use crucible_node_contract::{
    BindingCompatibility, ContentRef, Id, NodeDescriptor, ProviderManifest, ResourceLimits,
    Validate,
};
use serde::Serialize;

use crate::node_admission::{
    AdmissionEvidence, AdmissionLimits, AdmissionRequest, AdmittedGraph, EvidenceError,
    QualificationClaim, admit_graph,
};

use super::{
    ActivationRecord, NodeProvider, PreparedRealization, ProviderAuthorizationLease,
    ProviderAuthorizationScope, RealizationFailure, RuntimeCustodySlot, RuntimeLimits,
};

/// Bounds registration and planning independently of provider-advertised limits.
#[derive(Clone, Copy, Debug)]
pub struct ProviderRegistryLimits {
    /// Maximum simultaneously installed provider identities.
    pub providers: usize,
    /// Maximum profiles advertised by one installed provider.
    pub profiles: usize,
    /// Maximum original nodes requested from one provider.
    pub nodes: usize,
    /// Maximum canonical bytes in one complete manifest or preparation plan.
    pub metadata_bytes: usize,
}

impl Default for ProviderRegistryLimits {
    fn default() -> Self {
        Self {
            providers: 32,
            profiles: 256,
            nodes: 1024,
            metadata_bytes: 16 * 1024 * 1024,
        }
    }
}

/// Contains exact source-regenerated metadata before autonomous resources exist.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ProviderPreparationPlan {
    /// Complete immutable descriptors in ascending node order.
    pub descriptors: Vec<NodeDescriptor>,
    /// Complete durable compatibility records in the same node order.
    pub bindings: Vec<BindingCompatibility>,
}

/// Borrows finite original configuration without granting native allocation.
#[derive(Clone, Copy)]
pub struct ProviderPlanningRequest<'a> {
    /// Selects one exact installed profile.
    pub profile: &'a Id,
    /// Commits to the complete immutable configuration.
    pub configuration: &'a ContentRef,
    /// Complete original node roster, strictly ordered without duplicates.
    pub nodes: &'a [Id],
    /// Admitted process, descriptor, memory, storage and execution ceilings.
    pub resources: &'a ResourceLimits,
    /// Host metadata ceilings to enforce before constructing a returned plan.
    pub limits: ProviderRegistryLimits,
}

/// Reserves complete inactive custody before a provider can allocate resources.
pub struct OriginalRealizationRequest<'a> {
    /// Retains the exact independently accepted preallocation selection.
    pub selection: ProviderPlanningRequest<'a>,
    /// Borrows the accepted source-regenerated descriptor and compatibility plan.
    pub plan: &'a ProviderPreparationPlan,
    /// Original world/cut and complete expected owner incarnation roster.
    pub activation: &'a ActivationRecord,
    /// Complete runtime operation/routing ceilings.
    pub runtime_limits: RuntimeLimits,
    /// Pre-reserved whole-world custody, transferred into preparation on success.
    pub custody_slot: Box<dyn RuntimeCustodySlot>,
}

/// Authenticates installed source semantics separately from ordinary acceptance.
///
/// This host-configured inspector owns the exact measured implementation,
/// profile/schema codecs and original native preparation. A remote provider
/// response or an arbitrary request callback cannot install this authority.
pub trait InstalledProviderSource: AdmissionEvidence {
    /// Authenticates the complete source-built installed provider manifest.
    ///
    /// # Errors
    /// Refuses missing source ownership, changed artifacts or unsupported codecs.
    fn authenticate_provider(&self, manifest: &ProviderManifest) -> Result<(), EvidenceError>;

    /// Lends the source owner's exact retained original revision.
    ///
    /// This fence cannot replace source authentication. Withdrawing the source
    /// scope must revoke its same retained owner before this method returns.
    ///
    /// # Errors
    /// Defaults to refusal without original revision ownership.
    fn current_source_revision(
        &self,
        _scope: &ProviderAuthorizationScope,
    ) -> Result<ProviderAuthorizationLease, EvidenceError> {
        Err(refused("installed provider source revision is unsupported"))
    }

    /// Authenticates the exact immutable plan before any native allocation.
    ///
    /// # Errors
    /// Refuses foreign profiles, unsupported ports/state/modes or changed inputs.
    fn authenticate_plan(
        &self,
        manifest: &ProviderManifest,
        selection: ProviderPlanningRequest<'_>,
        plan: &ProviderPreparationPlan,
    ) -> Result<(), EvidenceError>;

    /// Authenticates the complete actual original inactive native realization.
    ///
    /// # Errors
    /// Refuses unresolved effects, changed configuration, foreign live owners or
    /// incomplete native/domain custody. Failure leaves preparation owned.
    fn authenticate_prepared(
        &self,
        manifest: &ProviderManifest,
        plan: &ProviderPreparationPlan,
        prepared: &PreparedRealization,
    ) -> Result<(), EvidenceError>;
}

/// Retains a revision beside independently installed behavioral evidence.
///
/// A lease is only a currency fence. Existing qualification callbacks and the
/// ordinary catalog's actual accepted-report/class checks remain mandatory.
pub trait InstalledProviderBehavioral: AdmissionEvidence {
    /// Lends the same original behavioral scope after authentic validation.
    ///
    /// # Errors
    /// Defaults to refusal without retained original revision support.
    fn current_behavioral_revision(
        &self,
        _scope: &ProviderAuthorizationScope,
    ) -> Result<ProviderAuthorizationLease, EvidenceError> {
        Err(refused(
            "installed provider behavioral revision is unsupported",
        ))
    }
}

/// Connects provider preparation to the ordinary catalog's normal class owner.
pub trait InstalledProviderClassAdmission: AdmissionEvidence {
    /// Lends currency of the same authenticated accepted report and required classes.
    ///
    /// No generic fence may replace absent class evidence. The implementing
    /// catalog still reauthenticates its complete actual ordinary acceptance.
    ///
    /// # Errors
    /// Defaults to refusal when that original policy scope has no revision owner.
    fn current_class_revision(
        &self,
        _scope: &ProviderAuthorizationScope,
    ) -> Result<ProviderAuthorizationLease, EvidenceError> {
        Err(refused("normal catalog class revision is unsupported"))
    }
}

/// Reports installation refusal separately from complete graph admission.
#[derive(Debug, thiserror::Error)]
pub enum ProviderAdmissionError {
    /// The exact source-installed provider is absent, changed or foreign.
    #[error(transparent)]
    Installation(EvidenceError),
    /// Complete source and behavioral graph admission refused.
    #[error(transparent)]
    Admission(crate::node_admission::AdmissionError),
}

struct InstalledProvider {
    manifest: ProviderManifest,
    provider: Box<dyn NodeProvider>,
    source: Rc<dyn InstalledProviderSource>,
    behavioral: Rc<dyn InstalledProviderBehavioral>,
}

/// Stores source-installed providers on their original owner thread.
///
/// Providers and nodes need neither `Send` nor `Sync`. Registration does not
/// grant readiness, execution, capture or acceptance of another configuration.
pub struct InstalledProviderRegistry {
    limits: ProviderRegistryLimits,
    providers: BTreeMap<Id, InstalledProvider>,
}

impl InstalledProviderRegistry {
    /// Creates a finite empty registry with no implicitly accepted provider.
    ///
    /// # Errors
    /// Refuses zero or wider-than-default registration/metadata ceilings.
    pub fn new(limits: ProviderRegistryLimits) -> Result<Self, EvidenceError> {
        let maximum = ProviderRegistryLimits::default();
        if limits.providers == 0
            || limits.providers > maximum.providers
            || limits.profiles == 0
            || limits.profiles > maximum.profiles
            || limits.nodes == 0
            || limits.nodes > maximum.nodes
            || limits.metadata_bytes == 0
            || limits.metadata_bytes > maximum.metadata_bytes
        {
            return Err(refused("invalid installed provider registry ceilings"));
        }
        Ok(Self {
            limits,
            providers: BTreeMap::new(),
        })
    }

    /// Installs one measured provider with separate source and behavioral owners.
    ///
    /// Native allocation is forbidden during this registration. The expected
    /// manifest comes from operator configuration, never a portable selection.
    /// Existing identities cannot be replaced, even by an equal manifest.
    ///
    /// # Errors
    /// Refuses changed manifests, duplicate/full registry, unsupported source or
    /// missing independently installed implementation authentication.
    pub fn install(
        &mut self,
        expected: &ProviderManifest,
        provider: Box<dyn NodeProvider>,
        source: Rc<dyn InstalledProviderSource>,
        behavioral: Rc<dyn InstalledProviderBehavioral>,
    ) -> Result<(), EvidenceError> {
        if self.providers.len() >= self.limits.providers
            || self.providers.contains_key(&expected.provider_id)
            || expected.supported_profiles.len() > self.limits.profiles
        {
            return Err(refused(
                "installed provider identity or profile credit exhausted",
            ));
        }
        credit(expected, self.limits.metadata_bytes)?;
        expected.validate().map_err(error)?;
        if provider.describe() != expected {
            return Err(refused(
                "provider differs from the original installed manifest",
            ));
        }
        source.authenticate_provider(expected)?;
        source.authenticate_implementation(&expected.implementation)?;
        behavioral.authenticate_implementation(&expected.implementation)?;
        self.providers.insert(
            expected.provider_id.clone(),
            InstalledProvider {
                manifest: expected.clone(),
                provider,
                source,
                behavioral,
            },
        );
        Ok(())
    }

    /// Borrows exact installed metadata without discovering or launching a peer.
    pub fn manifest(&self, provider: &Id) -> Option<&ProviderManifest> {
        self.providers
            .get(provider)
            .map(|installed| &installed.manifest)
    }

    /// Borrows complete installed manifests for capability discovery without launch.
    ///
    /// This reports operator-installed data, not qualification or ready authority.
    pub fn manifests(&self) -> impl ExactSizeIterator<Item = &ProviderManifest> {
        self.providers.values().map(|installed| &installed.manifest)
    }

    /// Prepares one exact original selection after both preallocation authorities.
    ///
    /// A complete returned `PreparedRealization` owns its handles before source
    /// validation. Errors and unwinds after that return retain its whole-world
    /// slot through supervised Drop. Before returning, the provider must retain
    /// partial allocation and negotiation in its own preowned guard or builder.
    ///
    /// # Errors
    /// Refuses absent/stale registration, changed plans, unaccepted behavioral
    /// claims, unavailable credits or actual native preparation/authentication.
    ///
    /// # Panics
    /// An installed provider or authenticator may unwind. Complete returned
    /// preparation uses supervised Drop; partial birth before return requires
    /// the provider's own guard or builder, as its preparation contract requires.
    pub fn prepare_original(
        &mut self,
        provider: &Id,
        selection: ProviderPlanningRequest<'_>,
        expected: &ProviderPreparationPlan,
        activation: &ActivationRecord,
        runtime_limits: RuntimeLimits,
        custody_slot: Box<dyn RuntimeCustodySlot>,
    ) -> Result<PreparedRealization, RealizationFailure> {
        self.prepare_original_inner(
            provider,
            OriginalRealizationRequest {
                selection,
                plan: expected,
                activation,
                runtime_limits,
                custody_slot,
            },
            None,
        )
    }

    /// Adds a final current host admission conjunction immediately before preparation.
    ///
    /// This additive gate cannot replace registered source or behavioral owners.
    /// Normal catalogs use their actual installed class policy here, after every
    /// planning callback and before the first native preparation effect.
    ///
    /// # Errors
    /// Retains the same original preparation on failure and refuses late revocation.
    ///
    /// # Panics
    /// An installed provider or authenticator may unwind. Complete returned
    /// preparation uses supervised Drop; partial birth before return requires
    /// the provider's own guard or builder, as its preparation contract requires.
    pub fn prepare_original_with_admission(
        &mut self,
        provider: &Id,
        request: OriginalRealizationRequest<'_>,
        final_admission: &dyn InstalledProviderClassAdmission,
    ) -> Result<PreparedRealization, RealizationFailure> {
        self.prepare_original_inner(provider, request, Some(final_admission))
    }

    fn prepare_original_inner(
        &mut self,
        provider: &Id,
        request: OriginalRealizationRequest<'_>,
        final_admission: Option<&dyn InstalledProviderClassAdmission>,
    ) -> Result<PreparedRealization, RealizationFailure> {
        let OriginalRealizationRequest {
            selection,
            plan: expected,
            activation,
            runtime_limits,
            custody_slot,
        } = request;
        let fail = |reason: EvidenceError| RealizationFailure {
            reason: reason.message,
            retained: None,
        };
        let installed = self
            .providers
            .get_mut(provider)
            .ok_or_else(|| fail(refused("provider is not independently installed")))?;
        let limits = self.limits;
        let selection = ProviderPlanningRequest {
            limits,
            ..selection
        };
        validate_selection(&installed.manifest, selection).map_err(fail)?;
        validate_plan(&installed.manifest, selection, expected).map_err(fail)?;
        custody_slot
            .validate_world(activation, runtime_limits)
            .map_err(|error| fail(refused(&error.to_string())))?;
        if installed.provider.describe() != &installed.manifest {
            return Err(fail(refused("installed provider manifest changed")));
        }
        installed
            .source
            .authenticate_provider(&installed.manifest)
            .map_err(fail)?;
        let plan = installed.provider.plan(selection)?;
        validate_plan(&installed.manifest, selection, &plan).map_err(fail)?;
        if &plan != expected {
            return Err(fail(refused(
                "authored descriptors/bindings differ from installed source plan",
            )));
        }
        installed
            .source
            .authenticate_plan(&installed.manifest, selection, &plan)
            .map_err(fail)?;
        for binding in &plan.bindings {
            let binding_hash = binding.identity().map_err(error).map_err(fail)?;
            let claim = || QualificationClaim::Node {
                binding,
                binding_hash: &binding_hash,
                qualification_refs: &binding.qualification_refs,
            };
            installed.source.qualify(claim()).map_err(fail)?;
            installed.behavioral.qualify(claim()).map_err(fail)?;
        }
        // Terminal reads occur after planning/qualification callbacks. They
        // cannot be replaced by acceptance data retained from an earlier scope.
        if let Some(evidence) = final_admission {
            for binding in &plan.bindings {
                let hash = binding.identity().map_err(error).map_err(fail)?;
                evidence
                    .qualify(QualificationClaim::Node {
                        binding,
                        binding_hash: &hash,
                        qualification_refs: &binding.qualification_refs,
                    })
                    .map_err(fail)?;
            }
        }
        installed
            .source
            .authenticate_provider(&installed.manifest)
            .map_err(fail)?;
        installed
            .behavioral
            .authenticate_implementation(&installed.manifest.implementation)
            .map_err(fail)?;
        let scope = ProviderAuthorizationScope::from_plan(selection, &plan).map_err(fail)?;
        // Retain the SAME actual class/source/evidence owners before the final
        // callbacks. No callback follows the direct currency reads below.
        let class_revision = final_admission
            .map(|evidence| evidence.current_class_revision(&scope))
            .transpose()
            .map_err(fail)?;
        let source_revision = installed
            .source
            .current_source_revision(&scope)
            .map_err(fail)?;
        let behavioral_revision = installed
            .behavioral
            .current_behavioral_revision(&scope)
            .map_err(fail)?;
        if installed.provider.describe() != &installed.manifest {
            return Err(fail(refused("provider changed during final admission")));
        }
        let authorization = super::provider_revision::ProviderPreparationAuthorization::new(
            scope,
            source_revision,
            behavioral_revision,
            class_revision,
        );
        authorization
            .authenticate(final_admission.is_some())
            .map_err(fail)?;
        let mut prepared = installed
            .provider
            .prepare_original(OriginalRealizationRequest {
                selection,
                plan: &plan,
                activation,
                runtime_limits,
                custody_slot,
            })?;
        // Keep the exact original fences beside actual native custody before
        // any metadata getter or source validator can unwind or revoke a role.
        prepared.provider_authorization = Some(authorization);
        let validated = (|| {
            if prepared.activation_record() != activation
                || prepared.limits != runtime_limits
                || prepared.nodes.len() != plan.descriptors.len()
                || prepared
                    .nodes
                    .iter()
                    .zip(&plan.descriptors)
                    .zip(&plan.bindings)
                    .any(|((node, descriptor), binding)| {
                        node.descriptor() != descriptor || &node.binding().compatibility != binding
                    })
            {
                return Err(refused(
                    "actual inactive realization differs from its accepted plan",
                ));
            }
            installed
                .source
                .authenticate_prepared(&installed.manifest, &plan, &prepared)?;
            prepared
                .provider_authorization
                .as_ref()
                .ok_or_else(|| refused("original provider authorization lost during validation"))?
                .authenticate(final_admission.is_some())
        })();
        match validated {
            Ok(()) => Ok(prepared),
            Err(reason) => Err(RealizationFailure {
                reason: reason.message,
                retained: Some(Box::new(prepared)),
            }),
        }
    }

    /// Borrows conjunctive installed evidence for ordinary host admission.
    ///
    /// The returned view retains the exact registration; it cannot install or
    /// replace an authority. A daemon can add its normal class-acceptance policy
    /// around this source/behavioral view before complete graph sealing.
    ///
    /// # Errors
    /// Refuses absent or currently unauthenticated provider installation.
    pub fn admission_evidence(
        &self,
        provider: &Id,
    ) -> Result<impl AdmissionEvidence + use<>, EvidenceError> {
        let installed = self
            .providers
            .get(provider)
            .ok_or_else(|| refused("provider not installed"))?;
        installed
            .source
            .authenticate_provider(&installed.manifest)?;
        Ok(ProviderEvidence {
            source: Rc::clone(&installed.source),
            behavioral: Rc::clone(&installed.behavioral),
        })
    }

    /// Seals a complete original graph through both independently installed authorities.
    ///
    /// The graph alone grants no activation. Callers keep the inactive capsule
    /// while admission callbacks execute and then use the common runtime barrier.
    ///
    /// # Errors
    /// Refuses missing registration or any ordinary/source admission requirement.
    pub fn admit_graph(
        &self,
        provider: &Id,
        request: AdmissionRequest<'_>,
        limits: AdmissionLimits,
    ) -> Result<AdmittedGraph, super::ProviderAdmissionError> {
        let installed = self.providers.get(provider).ok_or_else(|| {
            super::ProviderAdmissionError::Installation(refused("provider not installed"))
        })?;
        installed
            .source
            .authenticate_provider(&installed.manifest)
            .map_err(super::ProviderAdmissionError::Installation)?;
        if request.bindings.iter().any(|binding| {
            binding.compatibility.implementation != installed.manifest.implementation
        }) {
            return Err(super::ProviderAdmissionError::Installation(refused(
                "foreign implementation in provider graph",
            )));
        }
        let evidence = ProviderEvidence {
            source: Rc::clone(&installed.source),
            behavioral: Rc::clone(&installed.behavioral),
        };
        admit_graph(request, &evidence, limits).map_err(super::ProviderAdmissionError::Admission)
    }
}

struct ProviderEvidence {
    source: Rc<dyn InstalledProviderSource>,
    behavioral: Rc<dyn InstalledProviderBehavioral>,
}

impl AdmissionEvidence for ProviderEvidence {
    fn extension_registry(&self) -> Option<&crate::node_admission::InstalledExtensionRegistry> {
        self.source.extension_registry()
    }

    fn content(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, EvidenceError> {
        self.source.content(reference, maximum_bytes)
    }

    fn authenticate_implementation(
        &self,
        implementation: &crucible_node_contract::ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        self.source.authenticate_implementation(implementation)?;
        self.behavioral.authenticate_implementation(implementation)
    }

    fn authenticate_authority(
        &self,
        binding: &crucible_node_contract::NodeBinding,
    ) -> Result<(), EvidenceError> {
        self.source.authenticate_authority(binding)
    }

    fn authenticate_schema(
        &self,
        schema: &crucible_node_contract::SchemaRef,
    ) -> Result<(), EvidenceError> {
        self.source.authenticate_schema(schema)
    }

    fn qualify_capability(
        &self,
        world: &crucible_node_contract::WorldBinding,
        binding: &crucible_node_contract::NodeBinding,
        requirement: &crate::node_admission::NodeCapabilityRequirement,
    ) -> Result<(), EvidenceError> {
        self.source
            .qualify_capability(world, binding, requirement)?;
        self.behavioral
            .qualify_capability(world, binding, requirement)
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        // Claims borrow original scope, so both authorities inspect the same
        // value; no portable receipt becomes a replacement installation.
        self.source.qualify(claim.clone())?;
        self.behavioral.qualify(claim)
    }
}

fn validate_selection(
    manifest: &ProviderManifest,
    selection: ProviderPlanningRequest<'_>,
) -> Result<(), EvidenceError> {
    if selection.nodes.is_empty()
        || selection.nodes.len() > selection.limits.nodes
        || selection.nodes.windows(2).any(|pair| pair[0] >= pair[1])
        || !manifest
            .supported_profiles
            .iter()
            .any(|profile| &profile.profile_id == selection.profile)
    {
        return Err(refused(
            "provider selection is not a finite installed profile roster",
        ));
    }
    credit(
        &(
            selection.profile,
            selection.configuration,
            selection.nodes,
            selection.resources,
        ),
        selection.limits.metadata_bytes,
    )?;
    selection.configuration.validate().map_err(error)?;
    selection.resources.validate().map_err(error)
}

fn validate_plan(
    manifest: &ProviderManifest,
    selection: ProviderPlanningRequest<'_>,
    plan: &ProviderPreparationPlan,
) -> Result<(), EvidenceError> {
    if plan.descriptors.len() != selection.nodes.len()
        || plan.bindings.len() != selection.nodes.len()
    {
        return Err(refused("provider plan omits the original node roster"));
    }
    credit(plan, selection.limits.metadata_bytes)?;
    for ((descriptor, binding), node) in plan
        .descriptors
        .iter()
        .zip(&plan.bindings)
        .zip(selection.nodes)
    {
        descriptor.validate().map_err(error)?;
        binding.validate().map_err(error)?;
        if &descriptor.id != node
            || &binding.node_id != node
            || binding.implementation != manifest.implementation
            || descriptor.configuration_ref != binding.configuration_ref
            || binding.descriptor_hash != descriptor.identity().map_err(error)?
        {
            return Err(refused(
                "provider plan changes the installed implementation or configuration",
            ));
        }
    }
    Ok(())
}

pub(super) fn credit(value: &impl Serialize, maximum: usize) -> Result<(), EvidenceError> {
    struct Counter(usize);
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_sub(bytes.len())
                .ok_or_else(|| std::io::Error::other("provider metadata credit exhausted"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Counter(maximum), value).map_err(error)
}

fn error(error: impl std::fmt::Display) -> EvidenceError {
    refused(&error.to_string())
}

fn refused(message: &str) -> EvidenceError {
    EvidenceError {
        message: message.into(),
    }
}

#[cfg(test)]
#[path = "installed_provider_tests.rs"]
mod tests;
