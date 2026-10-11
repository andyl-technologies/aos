//! Enforces host behavioral acceptance before original CNP admission.
//!
//! This opt-in capsule retains actual checksum-process preparation. It exposes
//! no unchecked conversion into the legacy capsule and grants no graph or
//! execution authority. Native qualification remains a separate prerequisite.

use crucible_node_contract::{
    ClosedGateRecord, Id, NodeBinding, NodeDescriptor, OwnerBinding, ResourceLimits,
};
use crucible_node_provider::{bodies::RealizeResult, reference_service::ReferenceProfile};

use crate::{node_admission::AdmittedGraph, node_contract::OperationFailure};

use super::{
    CnpLaunchGuard, CnpPreparationFailure, CnpReferenceNode, CnpReferencePreparation,
    CnpReferenceQualification,
};

/// Borrows original native realization context without creating admission authority.
pub struct CnpAcceptanceScope<'a> {
    /// Borrows the actual original Child and pre-reserved supervisory custody.
    pub guard: &'a CnpLaunchGuard,
    /// Borrows the independently source-installed measured profile.
    pub profile: &'a ReferenceProfile,
    /// Borrows the complete original publicly realized response.
    pub realization: &'a RealizeResult,
    /// Borrows the exact actual node binding, including live incarnation scope.
    pub binding: &'a NodeBinding,
    /// Borrows complete original owner geometry and current owner binding.
    pub owner: &'a OwnerBinding,
    /// Borrows the exact original resource limits submitted to Realize.
    pub resources: &'a ResourceLimits,
    /// Borrows the original closed-gate evidence authenticated by native policy.
    pub gate: &'a ClosedGateRecord,
}

/// Authenticates current behavioral acceptance under independently installed policy.
///
/// The arguments come from the actual measured controller after discovery,
/// original realization, gate validation and native source authentication.
/// Implementations must bind every required class to complete original evidence
/// for this exact implementation, configuration, contracts and environment.
/// Provider assertions, protocol-only reports and historical acceptance cannot
/// implement this trusted host boundary by themselves.
pub trait CnpRealizationAcceptance {
    /// Reauthenticates the complete realized unit and its retained original report.
    ///
    /// # Errors
    /// Refuses missing policy/evidence, reduced classes, stale measurements,
    /// model-only evidence or changed source scope. The original native process
    /// remains owned on refusal; realization has already occurred.
    fn authenticate(&self, scope: CnpAcceptanceScope<'_>) -> Result<(), OperationFailure>;
}

/// Owns actual CNP preparation requiring fresh acceptance before node construction.
#[must_use = "original prepared process custody must survive until authentic reclamation"]
pub struct CnpAcceptedPreparation {
    inner: CnpReferencePreparation,
}

impl CnpAcceptedPreparation {
    /// Prepares the original native process and checks acceptance before wire Admit.
    ///
    /// This route requires an installed acceptance policy. Success does not open
    /// the world gate; complete graph admission, readiness and durable activation
    /// are still required. The original closed-reference route remains separate.
    ///
    /// # Errors
    /// Returns original guarded custody on native or behavioral refusal and on
    /// uncertain transport outcomes. It never retries with replacement IDs.
    pub fn prepare(
        guard: CnpLaunchGuard,
        native: &dyn CnpReferenceQualification,
        acceptance: &dyn CnpRealizationAcceptance,
    ) -> Result<Self, CnpPreparationFailure> {
        CnpReferencePreparation::prepare_checked(guard, native, Some(acceptance))
            .map(|inner| Self { inner })
    }

    /// Borrows the exact descriptor retained from the actual original realization.
    pub fn descriptor(&self) -> &NodeDescriptor {
        self.inner.descriptor()
    }

    /// Borrows the complete actual binding without granting native authority.
    pub fn binding(&self) -> &NodeBinding {
        self.inner.binding()
    }

    /// Borrows the original complete owner binding for whole-graph admission.
    pub fn owner_binding(&self) -> &OwnerBinding {
        self.inner.owner_binding()
    }

    /// Reauthenticates acceptance before installing the actual admitted native node.
    ///
    /// No historical Passed record substitutes for current evidence. Any failure
    /// retains the complete capsule through its pre-reserved supervisor slot.
    ///
    /// # Errors
    /// Refuses changed current evidence, graph/profile mismatch, stale native
    /// custody or exhausted original operation credits.
    pub fn into_node(
        self,
        graph: &AdmittedGraph,
        node: &Id,
        native: &dyn CnpReferenceQualification,
        acceptance: &dyn CnpRealizationAcceptance,
        maximum_operations: usize,
    ) -> Result<CnpReferenceNode, OperationFailure> {
        self.reauthenticate(native, acceptance)?;
        self.inner
            .into_node(graph, node, native, maximum_operations)
    }

    pub(super) fn reauthenticate(
        &self,
        native: &dyn CnpReferenceQualification,
        acceptance: &dyn CnpRealizationAcceptance,
    ) -> Result<(), OperationFailure> {
        let controller = self
            .inner
            .guard
            .custody
            .as_ref()
            .and_then(|custody| custody.controller.as_ref())
            .ok_or_else(|| {
                super::readiness::refused("original acceptance controller unavailable")
            })?;
        native.authenticate_provider(&self.inner.guard, &controller.profile)?;
        super::preparation::verify_companion(
            self.inner.companion_pid,
            self.inner.guard.provider_pid().ok_or_else(|| {
                super::readiness::refused("original acceptance provider unavailable")
            })?,
            &controller.profile,
        )?;
        let gate = controller
            .record(&self.inner.gate.record_ref)
            .map_err(|error| OperationFailure {
                effects: crate::node_contract::EffectKnowledge::Unknown,
                reason: error.to_string(),
            })?;
        native.authenticate_realization(
            &self.inner.guard,
            &self.inner.realization,
            &gate,
            self.inner.companion_pid,
        )?;
        acceptance.authenticate(CnpAcceptanceScope {
            guard: &self.inner.guard,
            profile: &controller.profile,
            realization: &self.inner.realization,
            binding: &self.inner.binding,
            owner: &self.inner.owner_binding,
            resources: &controller.bootstrap.resource_limits,
            gate: &gate,
        })
    }
}
