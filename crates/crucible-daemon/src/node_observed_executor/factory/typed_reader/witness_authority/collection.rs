//! Keeps collecting graph authority on the same original host witness object.
//!
//! Only explicit collecting callbacks substitute the unavailable behavioral
//! Node/extension qualification. Every structural/native/schema/source/world
//! premise remains current. Neither registry nor refused plan yields acceptance.

use super::super::TypedReaderCollectingExtensionPolicy;
use super::TypedReaderWitnessAuthority;
use crucible::node_admission::*;
use crucible_node_contract::*;
use std::{cell::OnceCell, rc::Rc};

pub(super) struct CollectionPolicy {
    installed: OnceCell<(
        Rc<InstalledExtensionRegistry>,
        Rc<TypedReaderCollectingExtensionPolicy>,
    )>,
}

impl CollectionPolicy {
    pub(super) fn new() -> Self {
        Self {
            installed: OnceCell::new(),
        }
    }
}

impl TypedReaderWitnessAuthority {
    /// Installs the independently configured fixture namespace once before sharing.
    ///
    /// The mutable borrow prevents a shared plan/Child holder from replacing its
    /// registry. Exact namespace, source and eight-axis checks remain separate
    /// from ordinary application/class qualification, which always refuses.
    ///
    /// # Errors
    /// Refuses duplicate installation, changed current plan or any source pin drift.
    pub fn configure_collection_extensions(
        &mut self,
        package: &ContentRef,
        publication: &ContentRef,
        handler: &ContentRef,
    ) -> Result<(), EvidenceError> {
        if self.collection.installed.get().is_some() {
            return Err(refused());
        }
        self.current_plan(&self.plan_reference).map_err(error)?;
        let policy = TypedReaderCollectingExtensionPolicy::configure(
            package,
            publication,
            handler,
            &self.source,
        )?;
        let registry = Rc::new(policy.install().map_err(error)?);
        self.current_plan(&self.plan_reference).map_err(error)?;
        self.collection
            .installed
            .set((registry, policy))
            .map_err(|_| refused())
    }

    /// Borrows the exact preinstalled registry after current plan reauthentication.
    ///
    /// This registry supplies semantics/peer negotiation only. Ordinary graph
    /// extension qualification and accepted-class issuance remain unavailable.
    ///
    /// # Errors
    /// Refuses missing independent installation or changed current fixture scope.
    pub fn collection_registry(&self) -> Result<Rc<InstalledExtensionRegistry>, EvidenceError> {
        self.current_plan(&self.plan_reference).map_err(error)?;
        self.collection
            .installed
            .get()
            .map(|(registry, _)| Rc::clone(registry))
            .ok_or_else(refused)
    }

    /// Borrows source-sealed public proof bodies under current original custody.
    ///
    /// The private oracle/enrollment holder never escapes. These historical
    /// bodies grant no execution, graph, class or publication ACK permission.
    ///
    /// # Errors
    /// Refuses an unenrolled case or changed current plan/kernel source scope.
    pub fn original_window_evidence(
        &self,
        case: &str,
    ) -> Result<
        std::cell::Ref<'_, super::super::OriginalTypedWindowSeal>,
        crucible_node_provider::ProviderError,
    > {
        self.current_plan(&self.plan_reference)?;
        let planned = self
            .programme
            .windows()
            .iter()
            .find(|window| window.case == case)
            .ok_or(crucible_node_provider::ProviderError::Correlation(
                "unplanned typed original window",
            ))?;
        self.source.current(&planned.node)?;
        let original = self.oracles.original(case)?;
        self.source.current(&planned.node)?;
        self.current_plan(&self.plan_reference)?;
        Ok(original)
    }

    fn collection_plan(&self, original: &ConformancePlanEvidence<'_>) -> Result<(), EvidenceError> {
        self.current_plan(original.plan_ref).map_err(error)?;
        let plan = super::encoded(&self.plan, self.limits.maximum_claim_bytes).map_err(error)?;
        let sources = self
            .source()
            .collection_source_references()
            .map_err(error)?;
        if original.plan_bytes != plan
            || original.refused_ref != self.audit.claim()
            || original.refused_bytes != self.audit.original_bytes()
            || original.world
                != &self
                    .source()
                    .collection_world()
                    .world()
                    .identity()
                    .map_err(error)?
            || original.sources != sources
        {
            return Err(refused());
        }
        original
            .plan_ref
            .verify(original.plan_bytes)
            .map_err(error)?;
        original
            .refused_ref
            .verify(original.refused_bytes)
            .map_err(error)?;
        self.current_plan(original.plan_ref).map_err(error)
    }
}

impl AdmissionEvidence for TypedReaderWitnessAuthority {
    fn extension_registry(&self) -> Option<&InstalledExtensionRegistry> {
        self.collection
            .installed
            .get()
            .map(|(registry, _)| registry.as_ref())
    }

    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, EvidenceError> {
        self.current_plan(&self.plan_reference).map_err(error)?;
        if reference == &self.plan_reference {
            let maximum = maximum.min(self.limits.maximum_claim_bytes);
            super::super::programme::count(&self.plan, maximum).map_err(error)?;
            let bytes = super::encoded(&self.plan, maximum).map_err(error)?;
            reference.verify(&bytes).map_err(error)?;
            return Ok(bytes);
        }
        if reference == self.audit.claim() {
            let bytes = self.audit.original_bytes();
            if bytes.len() > maximum
                || usize::try_from(reference.length.get()).map_err(error)? > maximum
            {
                return Err(refused());
            }
            reference.verify(bytes).map_err(error)?;
            return Ok(bytes.to_vec());
        }
        self.source()
            .public_content(reference, maximum)
            .map_err(error)
    }

    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        self.current_plan(&self.plan_reference).map_err(error)?;
        self.source()
            .authenticate_implementation(implementation)
            .map_err(error)
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        self.current_plan(&self.plan_reference).map_err(error)?;
        self.source().authenticate_binding(binding).map_err(error)
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        self.current_plan(&self.plan_reference).map_err(error)?;
        self.source().authenticate_schema(schema).map_err(error)
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        self.current_plan(&self.plan_reference).map_err(error)?;
        self.source()
            .authenticate_structural_claim(claim)
            .map_err(error)
    }
}

impl ConformanceAdmissionAuthority for TypedReaderWitnessAuthority {
    fn authenticate_collection_current_scope(
        &self,
        plan: ConformancePlanEvidence<'_>,
        request: AdmissionRequest<'_>,
    ) -> Result<(), EvidenceError> {
        self.collection_plan(&plan)?;

        // Source/world validation precedes the original private native read.
        // No vendor callback follows it in this authority. The selected SDK
        // separately fences its immutable schema and actual registrar at write.
        self.source()
            .authenticate_current_collection_scope(request)
            .map_err(error)
    }

    fn authenticate_collection_plan(
        &self,
        plan: ConformancePlanEvidence<'_>,
    ) -> Result<(), EvidenceError> {
        self.collection_plan(&plan)
    }

    fn authenticate_collection_world(
        &self,
        plan: ConformancePlanEvidence<'_>,
        request: AdmissionRequest<'_>,
    ) -> Result<(), EvidenceError> {
        self.collection_plan(&plan)?;
        self.source()
            .authenticate_collection_world(request)
            .map_err(error)?;
        self.collection_plan(&plan)
    }

    fn authenticate_collection_node(
        &self,
        plan: ConformancePlanEvidence<'_>,
        claim: QualificationClaim<'_>,
    ) -> Result<(), EvidenceError> {
        self.collection_plan(&plan)?;
        self.source()
            .authenticate_collection_node(claim)
            .map_err(error)?;
        self.collection_plan(&plan)
    }

    fn authenticate_collection_quantized(
        &self,
        plan: ConformancePlanEvidence<'_>,
        request: AdmissionRequest<'_>,
    ) -> Result<(), EvidenceError> {
        self.authenticate_collection_world(plan, request)
    }

    fn authenticate_collection_inputs(
        &self,
        plan: ConformancePlanEvidence<'_>,
        batch: &crucible::node_scheduling::RuntimeInputBatch,
    ) -> Result<(), EvidenceError> {
        self.collection_plan(&plan)?;
        self.source()
            .authenticate_collection_inputs(batch)
            .map_err(error)?;
        self.collection_plan(&plan)
    }

    fn authenticate_collection_operation(
        &self,
        plan: ConformancePlanEvidence<'_>,
        node: &Id,
        operation: &Id,
        request: &crucible::node_contract::OperationRequest,
    ) -> Result<(), EvidenceError> {
        self.collection_plan(&plan)?;
        self.source()
            .authenticate_collection_operation(node, operation, request)
            .map_err(error)?;
        self.collection_plan(&plan)
    }

    fn authenticate_collection_extension(
        &self,
        plan: ConformancePlanEvidence<'_>,
        application: &ExtensionApplication<'_>,
        declaration: &ExtensionDeclaration,
        selected: &ExtensionUse,
        semantics: &ExtensionSemanticContract,
    ) -> Result<(), EvidenceError> {
        self.collection_plan(&plan)?;
        let (_, policy) = self.collection.installed.get().ok_or_else(refused)?;
        policy.authenticate_collecting_application(
            application,
            declaration,
            selected,
            semantics,
        )?;
        self.collection_plan(&plan)
    }
    // Imported extension dependencies are unsupported by this fixed source;
    // its three exact core codec prerequisites retain installation checks.
}

fn error(error: impl std::fmt::Display) -> EvidenceError {
    EvidenceError {
        message: error.to_string(),
    }
}

fn refused() -> EvidenceError {
    EvidenceError {
        message: "typed collecting scope is outside the same installed original authority".into(),
    }
}
