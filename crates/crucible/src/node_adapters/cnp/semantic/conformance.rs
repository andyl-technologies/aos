//! Separates independently installed native collection from ordinary acceptance.
//!
//! Collection may drive an original realized provider to obtain missing evidence.
//! It never supplies an accepted class, changes the provider's guarantees, or
//! authorizes ordinary preparation through a partially executed report.

use crate::node_contract::{ActivationRecord, OperationFailure};

use super::{
    CnpSemanticInstallation, CnpSemanticNode, CnpSemanticProvider, CnpSemanticProviderFailure,
    CnpSemanticRealizationScope, InstalledCnpSemanticRole, refused,
};

/// Authenticates one source-installed collection fixture independently of acceptance.
///
/// The host installation owns its full normative witness population, exact
/// harness/program/configuration, realized oracles and bounded original journals.
/// It must keep every unexecuted or refused case explicit. These callbacks must
/// not interpret a portable Passed report as source or accepted-class authority.
/// Actual kernel identity and native source validation are checked separately.
pub trait CnpSemanticConformanceAuthority:
    crate::node_admission::ConformanceAdmissionAuthority
{
    /// Observes actual nested backing before allocation credit, using raw failures.
    ///
    /// Implementations walk the same concrete owner without heap allocation,
    /// formatting, serialization, I/O, or currentness callbacks. The caller
    /// separately charges the actual outer allocation and observer scratch.
    /// `None` retains an unknown owner. This default never calls the legacy
    /// allocating-error observer and grants no native or allocation authority.
    ///
    /// # Errors
    /// Returns a typed origin, busy-loan, unsupported-layout or checked-bound
    /// refusal without constructing an owned diagnostic.
    fn retained_requested_storage_precredit_data(
        &self,
        _maximum: usize,
    ) -> Result<Option<usize>, crate::node_contract::RuntimeError> {
        Ok(None)
    }

    /// Observes this same installed owner's nested requested storage as data.
    ///
    /// The caller charges the actual Rc header and inline payload separately.
    /// Supported concrete implementations walk their actual retained capacities
    /// and shared roots under original process/thread guards. None preserves an
    /// unresolved owner; neither a configured maximum nor encoded length is a
    /// backing observation. This grants no native, source or Capture authority.
    ///
    /// # Errors
    /// Refuses a foreign origin, unsupported mutable loan, arithmetic overflow
    /// or actual nested storage above the supplied bound.
    fn retained_requested_storage_data(
        &self,
        _maximum: usize,
    ) -> Result<Option<usize>, OperationFailure> {
        Ok(None)
    }

    /// Authenticates the complete original plan and source selection before realization.
    ///
    /// Callers that launch a process must also make this check before allocation.
    /// Registry enrollment and preparation repeat it on the retained selection.
    ///
    /// # Errors
    /// Defaults to refusal; implementations reject missing plans, changed source
    /// bindings, unsupported fixture scope and insufficient pre-effect credit.
    fn authenticate_installation(
        &self,
        _selection: &CnpSemanticInstallation,
    ) -> Result<(), OperationFailure> {
        Err(refused("generic installed conformance fixture is absent"))
    }

    /// Authenticates the actual original peer and native fixture state on every use.
    ///
    /// # Errors
    /// Defaults to refusal; implementations reject changed kernel/ELF identity,
    /// original body custody, native gate/result journals or fixture bounds.
    fn authenticate_realization(
        &self,
        _scope: CnpSemanticRealizationScope<'_>,
    ) -> Result<(), OperationFailure> {
        Err(refused(
            "generic original conformance realization is unauthenticated",
        ))
    }

    /// Reads the installed original scope immediately before a native request.
    ///
    /// This collecting-only terminal read follows source and node callbacks. It
    /// must check the retained plan, complete configured world and original
    /// source revision directly, without rerunning mutable vendor callbacks.
    /// The adapter then reads its actual owning capsule and SDK registrar before
    /// dispatch. Selected transport schema verification must be source-closed;
    /// this hook cannot fence arbitrary callbacks inside an unqualified driver.
    ///
    /// # Errors
    /// Defaults to refusal; rejects foreign or revoked plan/world/source, changed
    /// original native ownership, or an unqualified transport callback closure.
    fn authenticate_native_dispatch(
        &self,
        _scope: CnpSemanticRealizationScope<'_>,
        _plan: &crate::node_admission::InstalledConformancePlan,
    ) -> Result<(), OperationFailure> {
        Err(refused(
            "generic original conformance dispatch scope unavailable",
        ))
    }

    /// Authenticates the complete actual common graph before Admit and provider transfer.
    ///
    /// This checks the independently installed fixture, not ordinary accepted
    /// classes. A graph hash or decoded admission report alone is insufficient.
    ///
    /// # Errors
    /// Defaults to refusal; implementations reject omitted owners, changed world
    /// or scenario scope, unsupported source roles, or missing original evidence.
    fn authenticate_graph(
        &self,
        _scope: CnpSemanticRealizationScope<'_>,
        _graph: &crate::node_admission::ConformanceGraph,
    ) -> Result<(), OperationFailure> {
        Err(refused(
            "generic original conformance graph is unauthenticated",
        ))
    }
}

/// Retains a registered collection fixture without accepted-class authority.
///
/// Only the source registry constructs this capsule. Ordinary preparation cannot
/// accept it, and the collection policy is retained with the complete native owner.
pub struct InstalledCnpConformanceRole(pub(super) InstalledCnpSemanticRole);

/// Retains the actual admitted collection node without an ordinary node conversion.
pub struct CnpSemanticConformanceNode(pub(super) CnpSemanticNode);

impl CnpSemanticConformanceNode {
    /// Borrows this same admitted collecting node's actual retained route.
    ///
    /// This is data only and does not reauthenticate or grant an operation.
    pub fn original_conformance_route_data(&self) -> &crate::node_contract::NodeRoute {
        &self.0.route
    }

    /// Borrows facets from the exact original concrete Source of this node.
    ///
    /// The borrowed data does not replace the runtime's genuine graph and
    /// collection-scope gates or grant execution authority.
    ///
    /// # Errors
    /// Refuses a foreign Source, missing custody or foreign process/thread.
    pub fn original_conformance_facets_data<'a>(
        &self,
        source: &'a std::rc::Rc<super::PacketCompleteSemanticSource>,
    ) -> Result<&'a [crate::node_contract::FacetKind], crate::node_contract::RuntimeError> {
        self.0
            .preparation
            .guard
            .preparation_storage_origin_precredit_data()?;
        let native = self
            .0
            .preparation
            .guard
            .custody
            .as_ref()
            .ok_or(crate::node_contract::RuntimeError::OwnerUnavailable)?;
        let actual = native
            .source
            .as_ref()
            .ok_or(crate::node_contract::RuntimeError::OwnerUnavailable)?;
        let expected = super::CnpSemanticSource::installation(source.as_ref());
        // An erased Source can have duplicated vtables across codegen units.
        // Its data allocation and actual installation identify this occurrence.
        if std::rc::Rc::as_ptr(actual).cast::<()>() != std::rc::Rc::as_ptr(source).cast::<()>()
            || !std::ptr::eq(actual.installation(), expected)
        {
            return Err(crate::node_contract::RuntimeError::ForeignAuthority);
        }
        Ok(super::CnpSemanticSource::installation(source.as_ref())
            .facets
            .as_slice())
    }

    /// Transfers original native custody while retaining this collecting node's metadata.
    ///
    /// This is containment only. It grants no ordinary graph, renewed collection
    /// permission or native reclamation result.
    ///
    /// # Panics
    /// The original trusted supervisor must retain incoming custody without
    /// unwinding, as under the same native guard's Drop contract.
    pub fn retire_original(&mut self) {
        self.0.preparation.retire_original();
    }
}

/// Supplies an actual original fixture to the common runtime for evidence collection.
///
/// This separate provider reuses the native lifecycle and all original operation,
/// output, ACK and supervisor custody. It does not change the descriptor's claimed
/// capabilities, construct an acceptance token, or grant general vendor admission.
pub struct CnpSemanticConformanceProvider(CnpSemanticProvider);

impl CnpSemanticConformanceProvider {
    /// Retains the exact inactive fixture and its complete original activation proposal.
    ///
    /// # Errors
    /// Returns complete node custody on changed activation, used native state,
    /// missing current fixture authority, or failed source/kernel authentication.
    pub fn new(
        node: CnpSemanticConformanceNode,
        activation: ActivationRecord,
    ) -> Result<Self, CnpSemanticProviderFailure> {
        CnpSemanticProvider::new_installed(node.0, activation).map(Self)
    }

    /// Transfers the original fixture into its opaque collecting runtime.
    ///
    /// # Errors
    /// Retains original native custody on changed plan/world, failed collection
    /// authentication, mismatched original activation or exhausted runtime credit.
    pub fn prepare_conformance(
        mut self,
        graph: crate::node_admission::ConformanceGraph,
        limits: crate::node_contract::RuntimeLimits,
        custody_slot: Box<dyn crate::node_contract::RuntimeCustodySlot>,
    ) -> Result<
        crate::node_contract::ConformanceRuntime,
        crate::node_contract::ConformanceRuntimeFailure,
    > {
        self.0.prepare_collection(graph, limits, custody_slot)
    }
}
