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
