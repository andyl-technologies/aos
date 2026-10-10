//! Seals a source-authenticated collection world without ordinary Node acceptance.
//!
//! The opaque graph preserves every ordinary structural, content, schema and
//! ownership check. Only the Node behavioral claim uses explicit collection
//! authorization. Its private ordinary graph cannot escape through a getter or
//! serialized record, so missing class evidence cannot become ordinary admission.

use std::rc::Rc;

use crucible_node_contract::{
    ContentRef, HashRef, NodeBinding, NodeDescriptor, OwnerBinding, WorldBinding,
};

use super::*;

mod extensions;

const MAXIMUM_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;
const MAXIMUM_SOURCE_OBJECTS: usize = 32;

/// Borrows the complete independently installed collection plan and refused audit.
///
/// Neither document is acceptance authority. The installed callback must verify
/// the original normative population, exact unit/classes, current refused decision,
/// source/harness/fixtures and all original failed or unexecuted rows.
pub struct ConformancePlanEvidence<'a> {
    /// Identifies the complete original witness plan.
    pub plan_ref: &'a ContentRef,
    /// Retains its full canonical bytes.
    pub plan_bytes: &'a [u8],
    /// Identifies the original refused acceptance audit.
    pub refused_ref: &'a ContentRef,
    /// Retains every original audit row and its refused decision.
    pub refused_bytes: &'a [u8],
    /// Identifies the complete original world selected for collection.
    pub world: &'a HashRef,
    /// Identifies all independently installed source/harness/fixture prerequisites.
    pub sources: &'a [ContentRef],
}

/// Authenticates source-installed collection separately from ordinary acceptance.
///
/// Existing non-Node admission claims retain their original meanings through
/// [`AdmissionEvidence`]. Collection authorization must never issue an accepted
/// class or use vendor-selected omissions as a normative witness population.
pub trait ConformanceAdmissionAuthority: AdmissionEvidence {
    /// Reauthenticates the complete original refused plan and installed prerequisites.
    ///
    /// # Errors
    /// Defaults to refusal; rejects stale/accepted audits, changed complete plan,
    /// missing original bodies, wrong unit/classes or insufficient native credits.
    fn authenticate_collection_plan(
        &self,
        _plan: ConformancePlanEvidence<'_>,
    ) -> Result<(), EvidenceError> {
        Err(EvidenceError {
            message: "installed collection plan is unavailable".into(),
        })
    }

    /// Authorizes the complete actual world solely for its original collection plan.
    ///
    /// # Errors
    /// Defaults to refusal; rejects changed scenario, source bindings, omitted
    /// participants, unsupported native fixtures or a foreign original plan.
    fn authenticate_collection_world(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        _request: AdmissionRequest<'_>,
    ) -> Result<(), EvidenceError> {
        Err(EvidenceError {
            message: "installed collection world is unavailable".into(),
        })
    }

    /// Authorizes one exact Node behavioral claim for evidence collection only.
    ///
    /// # Errors
    /// Defaults to refusal; rejects unknown or changed source realization and
    /// any claim not covered by the complete original refused witness scope.
    fn authenticate_collection_node(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        _claim: QualificationClaim<'_>,
    ) -> Result<(), EvidenceError> {
        Err(EvidenceError {
            message: "installed collection Node scope is unavailable".into(),
        })
    }

    /// Authenticates one exact installed extension solely for original collection.
    ///
    /// Namespace publication, actual features, schema bounds, immutable handler
    /// and every semantic axis remain checked by the original registry. This
    /// callback replaces only ordinary behavioral application qualification.
    ///
    /// # Errors
    /// Defaults to refusal; rejects foreign or stale scope, missing source/native
    /// custody, unsupported interpretation or incomplete original fixture plan.
    fn authenticate_collection_extension(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        _application: &ExtensionApplication<'_>,
        _declaration: &crucible_node_contract::ExtensionDeclaration,
        _selected: &crucible_node_contract::ExtensionUse,
        _semantics: &ExtensionSemanticContract,
    ) -> Result<(), EvidenceError> {
        Err(failure("installed collection extension is unavailable"))
    }

    /// Authenticates an imported extension under its original collection root.
    ///
    /// # Errors
    /// Defaults to refusal; rejects unknown dependency semantics, changed root
    /// scope or unavailable independently installed original fixture evidence.
    fn authenticate_collection_extension_dependency(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        _application: &ExtensionApplication<'_>,
        _selected_root: &crucible_node_contract::ExtensionUse,
        _dependent: &crucible_node_contract::ExtensionDeclaration,
        _prerequisite: &crucible_node_contract::ExtensionDeclaration,
        _semantics: &ExtensionSemanticContract,
    ) -> Result<(), EvidenceError> {
        Err(failure(
            "installed collection extension dependency is unavailable",
        ))
    }

    /// Reads the final installed revision of the complete original collecting scope.
    ///
    /// This trusted host authority reads the exact plan, world, selected nodes,
    /// owners and current source/native-owner revision after preceding callbacks.
    /// It must not delegate to vendor or node callbacks: no such callback may
    /// follow this final read before collection dispatch. Portable reports and
    /// advertised policy flags cannot establish this current revision.
    ///
    /// # Errors
    /// Defaults to refusal; rejects absent final revision authority, independently
    /// revoked world/node/native custody or any changed original scope.
    fn authenticate_collection_current_scope(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        _request: AdmissionRequest<'_>,
    ) -> Result<(), EvidenceError> {
        Err(failure(
            "current installed collection revision is unavailable",
        ))
    }

    /// Authorizes internal quantized input collection for the complete original world.
    ///
    /// # Errors
    /// Defaults to refusal; rejects unsupported input roles, source fixtures,
    /// operating contracts or a plan lacking complete native staging custody.
    fn authenticate_collection_quantized(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        _request: AdmissionRequest<'_>,
    ) -> Result<(), EvidenceError> {
        Err(failure(
            "installed quantized collection lifecycle is unavailable",
        ))
    }

    /// Authenticates the scheduler's complete original batch before native Stage.
    ///
    /// # Errors
    /// Defaults to refusal; rejects changed producer closure, payloads, routes,
    /// input identities, cuts, plan scope or unavailable native custody credit.
    fn authenticate_collection_inputs(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        _batch: &crate::node_scheduling::RuntimeInputBatch,
    ) -> Result<(), EvidenceError> {
        Err(failure(
            "installed original collection input custody is unavailable",
        ))
    }

    /// Authorizes an exact original collection request before its native Begin.
    ///
    /// # Errors
    /// Defaults to refusal; rejects changed node/operation/window, unsupported
    /// effects, or exhausted original fixture/native result credit.
    fn authenticate_collection_operation(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        _node: &crucible_node_contract::Id,
        _operation: &crucible_node_contract::Id,
        _request: &crate::node_contract::OperationRequest,
    ) -> Result<(), EvidenceError> {
        Err(failure(
            "installed original collection request is unavailable",
        ))
    }
}

struct Plan {
    plan_ref: ContentRef,
    plan_bytes: Vec<u8>,
    refused_ref: ContentRef,
    refused_bytes: Vec<u8>,
    world: HashRef,
    sources: Vec<ContentRef>,
    authority: Rc<dyn ConformanceAdmissionAuthority>,
}

/// Retains a host-authenticated refused collection scope without acceptance authority.
///
/// Construction precredits both complete documents before parsing or copying.
/// Fresh installation authentication is repeated before every collection effect.
/// There is no decoded constructor, public Clone, or accepted-token conversion.
pub struct InstalledConformancePlan(Rc<Plan>);

impl InstalledConformancePlan {
    /// Authenticates and retains the complete independently installed original plan.
    ///
    /// # Errors
    /// Refuses documents above 8 MiB each, missing/overwide source rosters,
    /// corrupt content identities, noncanonical JSON or failed installed policy.
    pub fn install(
        evidence: ConformancePlanEvidence<'_>,
        authority: Rc<dyn ConformanceAdmissionAuthority>,
    ) -> Result<Self, EvidenceError> {
        if evidence.plan_bytes.len() > MAXIMUM_DOCUMENT_BYTES
            || evidence.refused_bytes.len() > MAXIMUM_DOCUMENT_BYTES
            || evidence.sources.is_empty()
            || evidence.sources.len() > MAXIMUM_SOURCE_OBJECTS
            || evidence.sources.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(failure(
                "collection document or source credit is unsupported",
            ));
        }
        for (reference, bytes) in [
            (evidence.plan_ref, evidence.plan_bytes),
            (evidence.refused_ref, evidence.refused_bytes),
        ] {
            reference
                .verify(bytes)
                .map_err(|error| failure(error.to_string()))?;
            let parsed =
                crucible_node_contract::canonical::parse_json(bytes, MAXIMUM_DOCUMENT_BYTES)
                    .map_err(|error| failure(error.to_string()))?;
            if crucible_node_contract::canonical::canonical_json(&parsed)
                .map_err(|error| failure(error.to_string()))?
                != bytes
            {
                return Err(failure("collection documents are not canonical originals"));
            }
        }
        authority.authenticate_collection_plan(evidence.borrowed())?;
        Ok(Self(Rc::new(Plan {
            plan_ref: evidence.plan_ref.clone(),
            plan_bytes: evidence.plan_bytes.to_vec(),
            refused_ref: evidence.refused_ref.clone(),
            refused_bytes: evidence.refused_bytes.to_vec(),
            world: evidence.world.clone(),
            sources: evidence.sources.to_vec(),
            authority,
        })))
    }

    /// Borrows the complete original plan/audit bytes without copying them.
    pub fn evidence(&self) -> ConformancePlanEvidence<'_> {
        ConformancePlanEvidence {
            plan_ref: &self.0.plan_ref,
            plan_bytes: &self.0.plan_bytes,
            refused_ref: &self.0.refused_ref,
            refused_bytes: &self.0.refused_bytes,
            world: &self.0.world,
            sources: &self.0.sources,
        }
    }

    /// Reauthenticates the current installed policy and every retained original body.
    ///
    /// # Errors
    /// Refuses revoked/changed host installation or original collection scope.
    pub fn reauthenticate(&self) -> Result<(), EvidenceError> {
        self.0
            .authority
            .authenticate_collection_plan(self.evidence())
    }

    /// Reauthenticates membership of the exact retained host authority object.
    ///
    /// Matching portable plan bytes or another policy object cannot satisfy this
    /// identity check. Success grants no ordinary execution permission.
    ///
    /// # Errors
    /// Refuses foreign host authority or revoked original plan/source scope.
    pub fn authenticate_authority(
        &self,
        authority: &dyn ConformanceAdmissionAuthority,
    ) -> Result<(), EvidenceError> {
        if !self.has_authority(authority) {
            return Err(failure("foreign retained collection authority"));
        }
        self.reauthenticate()
    }

    pub(crate) fn retained(&self) -> Self {
        Self(Rc::clone(&self.0))
    }

    // A source fixture must retain the very same installed authority, not merely
    // reproduce its portable plan bytes through a different policy object.
    // Trait vtables may be duplicated by code generation; object identity must
    // compare the retained authority data address rather than that metadata.
    pub(crate) fn has_authority(&self, authority: &dyn ConformanceAdmissionAuthority) -> bool {
        std::ptr::addr_eq(self.0.authority.as_ref(), authority)
    }

    pub(crate) fn same_original(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

impl ConformancePlanEvidence<'_> {
    fn borrowed(&self) -> ConformancePlanEvidence<'_> {
        ConformancePlanEvidence {
            plan_ref: self.plan_ref,
            plan_bytes: self.plan_bytes,
            refused_ref: self.refused_ref,
            refused_bytes: self.refused_bytes,
            world: self.world,
            sources: self.sources,
        }
    }
}

/// Retains a complete collection-only graph without an ordinary graph conversion.
///
/// World and descriptor bytes retain their existing formats. The collection
/// purpose stays in this nonserialized host capsule and cannot be reconstructed
/// from those bytes. Native/runtime ownership remains a separate requirement.
pub struct ConformanceGraph {
    pub(crate) graph: AdmittedGraph,
    pub(crate) plan: InstalledConformancePlan,
    descriptors: Vec<NodeDescriptor>,
    bindings: Vec<NodeBinding>,
    owners: Vec<OwnerBinding>,
}

impl ConformanceGraph {
    /// Borrows the original complete immutable world without its ordinary seal.
    pub fn world(&self) -> &WorldBinding {
        self.graph.world()
    }

    /// Borrows the original complete collection plan and refused audit.
    pub fn plan(&self) -> &InstalledConformancePlan {
        &self.plan
    }

    /// Reauthenticates the original complete world and installed collection policy.
    ///
    /// # Errors
    /// Refuses stale plan/source authority or changed complete collection scope.
    pub fn reauthenticate(&self) -> Result<(), EvidenceError> {
        self.plan.reauthenticate()?;
        self.plan
            .0
            .authority
            .authenticate_collection_world(self.plan.evidence(), self.request())?;
        for binding in &self.bindings {
            let identity = binding
                .compatibility
                .identity()
                .map_err(|error| failure(error.to_string()))?;
            self.plan.0.authority.authenticate_collection_node(
                self.plan.evidence(),
                QualificationClaim::Node {
                    binding: &binding.compatibility,
                    binding_hash: &identity,
                    qualification_refs: &binding.compatibility.qualification_refs,
                },
            )?;
        }
        self.authenticate_current_scope()
    }

    pub(crate) fn authenticate_quantized(&self) -> Result<(), EvidenceError> {
        self.reauthenticate()?;
        self.plan
            .0
            .authority
            .authenticate_collection_quantized(self.plan.evidence(), self.request())?;
        self.authenticate_current_scope()
    }

    pub(crate) fn authenticate_inputs(
        &self,
        batch: &crate::node_scheduling::RuntimeInputBatch,
    ) -> Result<(), EvidenceError> {
        self.authenticate_quantized()?;
        self.plan
            .0
            .authority
            .authenticate_collection_inputs(self.plan.evidence(), batch)?;
        self.authenticate_current_scope()
    }

    pub(crate) fn authenticate_operation(
        &self,
        node: &crucible_node_contract::Id,
        operation: &crucible_node_contract::Id,
        request: &crate::node_contract::OperationRequest,
    ) -> Result<(), EvidenceError> {
        self.reauthenticate()?;
        self.plan.0.authority.authenticate_collection_operation(
            self.plan.evidence(),
            node,
            operation,
            request,
        )?;
        // The case callback can revoke its installation while returning success.
        // The final installed revision also covers independently revoked world,
        // node and native-owner scope; a plan-only check cannot establish it.
        self.authenticate_current_scope()
    }

    pub(crate) fn authenticate_current_scope(&self) -> Result<(), EvidenceError> {
        self.plan.reauthenticate()?;
        self.plan
            .0
            .authority
            .authenticate_collection_current_scope(self.plan.evidence(), self.request())
    }

    fn request(&self) -> AdmissionRequest<'_> {
        AdmissionRequest {
            world: self.graph.world(),
            descriptors: &self.descriptors,
            bindings: &self.bindings,
            owners: &self.owners,
            requirements: self.graph.requirements(),
        }
    }
}

/// Seals only an independently authorized original collection world.
///
/// Every ordinary admission check remains. Only Node behavioral qualification
/// is replaced by the explicit installed collection callback; all other claims
/// are delegated unchanged. No accepted class or ordinary graph is returned.
///
/// # Errors
/// Refuses wrong plan/world/source, failed default authority, missing ordinary
/// structural/schema/ownership evidence, or exhausted unchanged admission limits.
pub fn admit_conformance_graph(
    request: AdmissionRequest<'_>,
    plan: &InstalledConformancePlan,
    limits: AdmissionLimits,
) -> Result<ConformanceGraph, AdmissionError> {
    super::nodes::check_core(&request, limits)?;
    authenticate_original_scope(request, plan)?;
    let delegated = CollectionEvidence { plan };
    let mut graph = super::admit_graph_for_purpose(request, &delegated, limits, Some(plan))?;
    graph.collecting = true;
    Ok(ConformanceGraph {
        graph,
        plan: plan.retained(),
        descriptors: request.descriptors.to_vec(),
        bindings: request.bindings.to_vec(),
        owners: request.owners.to_vec(),
    })
}

// Admission callbacks may revoke the installation even after extension checks.
// The final call runs before retaining any returned graph or collection seal.
pub(super) fn authenticate_original_scope(
    request: AdmissionRequest<'_>,
    plan: &InstalledConformancePlan,
) -> Result<(), AdmissionError> {
    let checked = (|| {
        plan.reauthenticate()?;
        if request
            .world
            .identity()
            .map_err(|error| failure(error.to_string()))?
            != *plan.evidence().world
        {
            return Err(failure(
                "collection world differs from original refused plan",
            ));
        }
        plan.0
            .authority
            .authenticate_collection_world(plan.evidence(), request)?;
        plan.reauthenticate()?;
        plan.0
            .authority
            .authenticate_collection_current_scope(plan.evidence(), request)
    })();
    checked.map_err(|error| {
        super::error::refuse(
            AdmissionStage::Authenticate,
            AdmissionSubject::World,
            AdmissionCode::QualificationUnavailable,
            "current original source-installed collection plan",
            &error.message,
        )
    })
}

struct CollectionEvidence<'a> {
    plan: &'a InstalledConformancePlan,
}

impl AdmissionEvidence for CollectionEvidence<'_> {
    fn extension_registry(&self) -> Option<&InstalledExtensionRegistry> {
        self.plan.0.authority.extension_registry()
    }
    fn content(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, EvidenceError> {
        self.plan.0.authority.content(reference, maximum_bytes)
    }
    fn authenticate_implementation(
        &self,
        implementation: &crucible_node_contract::ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        self.plan
            .0
            .authority
            .authenticate_implementation(implementation)
    }
    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        self.plan.0.authority.authenticate_authority(binding)
    }
    fn authenticate_schema(
        &self,
        schema: &crucible_node_contract::SchemaRef,
    ) -> Result<(), EvidenceError> {
        self.plan.0.authority.authenticate_schema(schema)
    }
    fn qualify_capability(
        &self,
        world: &WorldBinding,
        binding: &NodeBinding,
        requirement: &NodeCapabilityRequirement,
    ) -> Result<(), EvidenceError> {
        self.plan
            .0
            .authority
            .qualify_capability(world, binding, requirement)
    }
    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        self.plan.reauthenticate()?;
        match claim {
            QualificationClaim::Node { .. } => self
                .plan
                .0
                .authority
                .authenticate_collection_node(self.plan.evidence(), claim),
            _ => self.plan.0.authority.qualify(claim),
        }
    }
}

fn failure(message: impl Into<String>) -> EvidenceError {
    EvidenceError {
        message: message.into(),
    }
}
