//! Validates historical archive structure under actual installed code before Child.
//!
//! This owns the same structural graph implementation used by admission, with a
//! distinct opaque result. Its code-selection callbacks cannot produce a live
//! collecting graph, ordinary runtime graph, native hold or accepted class.

use super::*;
use crate::node_state::{NativeWorldFactory, StateError};

/// Retains complete archive-code validation without a live graph conversion.
///
/// Construction authenticates the original installed plan and concrete code
/// factory, then runs the existing full structural/content/schema/causality
/// validators. Private graph storage is never exposed as an admitted or live
/// collecting graph. Fresh native graph admission retains all existing guards.
pub struct CompleteArchiveCodeGraph {
    pub(crate) graph: AdmittedGraph,
    plan: InstalledConformancePlan,
    process: u32,
    thread: std::thread::ThreadId,
}

impl CompleteArchiveCodeGraph {
    fn authenticate_origin(&self) -> Result<(), crate::node_contract::RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(crate::node_contract::RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Counts this actual code graph and plan, excluding its authority backing.
    ///
    /// The inline graph root and private plan backing are included; a caller's
    /// enclosing Rc/Box header and actual installed authority/source owners are
    /// separate simultaneous terms. The code factory observes its concrete
    /// prebirth authority rather than invoking a live-node backing callback.
    /// Native, allocator residency and compiler frames remain independent.
    ///
    /// # Errors
    /// Refuses foreign creation, expired/revoked code selection, unknown erased
    /// authority ownership, conflicting identities or requested-storage excess.
    pub fn retained_requested_storage_excluding_authority_data(
        &self,
        maximum: usize,
    ) -> Result<usize, crate::node_contract::RuntimeError> {
        self.authenticate_origin()?;
        self.plan
            .reauthenticate()
            .map_err(|_| crate::node_contract::RuntimeError::ForeignAuthority)?;
        let bytes = self.original_retained_requested_storage_data(maximum)?;
        self.plan
            .reauthenticate()
            .map_err(|_| crate::node_contract::RuntimeError::ForeignAuthority)?;
        Ok(bytes)
    }

    /// Observes actual retained code-graph storage without currency callbacks.
    ///
    /// Creation custody is checked before owner access. Revocation does not free
    /// these allocations; this method grants no code, graph or native permission.
    /// The caller counts actual authority backing and counter scratch separately.
    ///
    /// # Errors
    /// Refuses a foreign creator, checked overflow or requested-storage excess.
    pub fn original_retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, crate::node_contract::RuntimeError> {
        use crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter;
        self.authenticate_origin()?;
        let mut counter = RetainedRuntimeCounter::new(maximum);
        counter.add(std::mem::size_of::<Self>())?;
        self.graph.charge_original_retained_storage(&mut counter)?;
        counter.add(
            self.plan
                .retained_allocation_bytes_excluding_authority_precredit_data()?,
        )?;
        self.authenticate_origin()?;
        Ok(counter.bytes())
    }

    /// Returns the compiled fixed scratch of the actual requested-storage walker.
    ///
    /// The caller admits this separate simultaneous counter before invoking the
    /// walk. This is not compiler stack, allocator physical peak or permission.
    pub fn retained_requested_storage_scratch_bytes() -> usize {
        std::mem::size_of::<crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter>()
    }

    /// Authenticates a borrowed graph as this exact private structural result.
    ///
    /// The comparison extracts no graph or runtime and grants no native rights.
    /// It binds a trusted historical codec callback to its actual retained owner.
    ///
    /// # Errors
    /// Refuses another creator or a different original graph allocation.
    pub fn authenticate_original_graph_data(
        &self,
        graph: &AdmittedGraph,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        self.authenticate_origin()?;
        if !std::ptr::eq(&self.graph, graph) {
            return Err(crate::node_contract::RuntimeError::ForeignAuthority);
        }
        self.authenticate_origin()
    }

    /// Borrows the actual installed code plan, without creating native currentness.
    pub fn plan(&self) -> &InstalledConformancePlan {
        &self.plan
    }

    pub(crate) fn authenticate_archive_source(
        &self,
        factory: &dyn NativeWorldFactory,
        archive: &crate::node_state::NativeArchiveRecord,
        scope: &crate::node_state::CollectingCompleteCaptureProvenance,
    ) -> Result<(), StateError> {
        self.authenticate_origin()
            .map_err(crate::node_state::schema)?;
        self.plan
            .reauthenticate()
            .map_err(crate::node_state::schema)?;
        factory.authenticate_complete_collecting_archive_code_source(
            &self.plan,
            &self.graph,
            archive,
            scope,
        )?;
        self.plan
            .reauthenticate()
            .map_err(crate::node_state::schema)
    }
}

/// Validates a complete code-selection world without authorizing native preparation.
///
/// Every structural validator is shared with ordinary graph admission. Code
/// factory callbacks replace only collecting behavioral/profile authorization;
/// no accepted graph or ordinary seal is returned. Unsupported code classes
/// and extensions retain their original refusals.
///
/// # Errors
/// Refuses malformed/overwide records, foreign installed plan/factory, missing
/// exact bodies, unsupported static class/profile or structural inconsistency.
pub fn admit_complete_archive_code_graph(
    request: AdmissionRequest<'_>,
    plan: &InstalledConformancePlan,
    factory: &dyn NativeWorldFactory,
    limits: AdmissionLimits,
) -> Result<CompleteArchiveCodeGraph, AdmissionError> {
    super::super::nodes::check_core(&request, limits)?;
    super::super::evidence::bounded_core(request.requirements, limits.maximum_core_object_bytes)?;
    authenticate_code_request(request, plan, factory)?;
    let evidence = ArchiveCodeEvidence { plan, factory };
    // No collecting extension callback may be smuggled through this code-only
    // route. The existing None path keeps unsupported extension forms closed.
    let mut graph = super::super::admit_graph_for_purpose(request, &evidence, limits, None)?;
    if !graph.selected_extensions().is_empty() {
        return Err(super::super::error::refuse(
            AdmissionStage::Authenticate,
            AdmissionSubject::World,
            AdmissionCode::QualificationUnavailable,
            "closed complete archive code graph",
            "code graph extensions are unsupported",
        ));
    }
    authenticate_code_request(request, plan, factory)?;
    graph.collecting = true;
    Ok(CompleteArchiveCodeGraph {
        graph,
        plan: plan.retained(),
        process: std::process::id(),
        thread: std::thread::current().id(),
    })
}

fn authenticate_code_request(
    request: AdmissionRequest<'_>,
    plan: &InstalledConformancePlan,
    factory: &dyn NativeWorldFactory,
) -> Result<(), AdmissionError> {
    let checked = (|| {
        plan.reauthenticate()?;
        if request
            .world
            .identity()
            .map_err(|error| failure(error.to_string()))?
            != *plan.evidence().world
        {
            return Err(failure("archive code world differs from installed plan"));
        }
        factory
            .authenticate_complete_archive_code_request(plan, request)
            .map_err(|error| failure(error.to_string()))?;
        plan.reauthenticate()
    })();
    checked.map_err(|error| {
        super::super::error::refuse(
            AdmissionStage::Authenticate,
            AdmissionSubject::World,
            AdmissionCode::QualificationUnavailable,
            "installed complete archive code selection",
            &error.message,
        )
    })
}

struct ArchiveCodeEvidence<'a> {
    plan: &'a InstalledConformancePlan,
    factory: &'a dyn NativeWorldFactory,
}

impl AdmissionEvidence for ArchiveCodeEvidence<'_> {
    fn extension_registry(&self) -> Option<&InstalledExtensionRegistry> {
        self.plan.0.authority.extension_registry()
    }

    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, EvidenceError> {
        self.plan.0.authority.content(reference, maximum)
    }

    fn authenticate_implementation(
        &self,
        identity: &crucible_node_format::ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        self.plan.0.authority.authenticate_implementation(identity)
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        self.plan.0.authority.authenticate_authority(binding)
    }

    fn authenticate_schema(
        &self,
        schema: &crucible_node_format::SchemaRef,
    ) -> Result<(), EvidenceError> {
        self.plan.0.authority.authenticate_schema(schema)
    }

    fn authenticate_schema_roster(
        &self,
        binding: &NodeBinding,
        schemas: &[crucible_node_format::SchemaRef],
    ) -> Option<Result<(), EvidenceError>> {
        self.plan
            .0
            .authority
            .authenticate_complete_archive_code_schema_roster(self.plan, binding, schemas)
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
            QualificationClaim::Node { .. } | QualificationClaim::Capture { .. } => self
                .factory
                .authenticate_complete_archive_code_claim(self.plan, claim)
                .map_err(|error| failure(error.to_string())),
            _ => self.plan.0.authority.qualify(claim),
        }
    }
}

impl InstalledConformancePlan {
    /// Compares the actual private plan allocation without a currency callback.
    ///
    /// Equal serialized plans do not satisfy this data-identity comparison. It
    /// authenticates neither creator/currentness nor a node, grant or class;
    /// callers must retain and authenticate their actual original owner scope.
    pub fn is_original_plan_data(&self, other: &Self) -> bool {
        self.same_original(other)
    }
}
