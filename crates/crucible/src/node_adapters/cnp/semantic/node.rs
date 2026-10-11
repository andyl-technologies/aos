//! Owns generic original admission and the source-qualified common node capsule.

use std::rc::Rc;

use crucible_node_contract::{Extensions, Id};
use crucible_node_provider::{bodies::*, client::CnpController, envelope::Method};

use crate::{
    node_admission::AdmittedGraph,
    node_contract::{NodeRoute, OperationFailure, OwnerIdentity, ThreadAffinity},
};

use super::{
    CnpSemanticPreparation, CnpSemanticRealizationScope, CnpSemanticSource,
    preparation::request_id, refused, state::SemanticRuntimeCustody, unknown,
};

/// Retains the complete actual original realization when common admission fails.
pub struct CnpSemanticAdmissionFailure {
    /// Records original uncertainty without claiming rollback or reclamation.
    pub error: OperationFailure,
    /// Owns native resources, current policies and all immutable transport journals.
    pub preparation: Box<CnpSemanticPreparation>,
}

/// Owns one source-installed generic CNP role beneath actual common authority.
///
/// The adapter never interprets vendor-defined native facts without its installed
/// oracle and current acceptance policy. All original semantic state lives in
/// the native resource capsule transferred to its pre-reserved supervisor on Drop.
#[must_use = "retain the original common node or transfer its complete native custody"]
pub struct CnpSemanticNode {
    pub(super) preparation: Box<CnpSemanticPreparation>,
    pub(super) route: NodeRoute,
    pub(super) exact_profile: Id,
    pub(super) affinity: ThreadAffinity,
}

impl CnpSemanticPreparation {
    /// Admits the exact original realization against an independently admitted graph.
    ///
    /// Current behavioral acceptance and actual native/source validation precede
    /// remote Admit. A failed original attempt cannot be replaced through this
    /// capsule. The accepted response remains in its original transport journal.
    ///
    /// # Errors
    /// Retains the complete original preparation on changed graph/configuration,
    /// failed current qualification, refused admission or uncertain transport effects.
    pub fn into_node(
        self,
        graph: &AdmittedGraph,
    ) -> Result<CnpSemanticNode, CnpSemanticAdmissionFailure> {
        if graph.collecting {
            return Err(CnpSemanticAdmissionFailure {
                error: refused("ordinary node refuses collecting graph purpose"),
                preparation: Box::new(self),
            });
        }
        if self
            .guard
            .custody
            .as_ref()
            .is_some_and(|native| native.conformance.is_some())
        {
            return Err(CnpSemanticAdmissionFailure {
                error: refused("ordinary node admission refuses conformance-only custody"),
                preparation: Box::new(self),
            });
        }
        self.into_node_installed(graph)
    }

    /// Admits the actual original fixture through its independent complete graph policy.
    ///
    /// # Errors
    /// Retains all original resources on missing fixture policy, changed graph,
    /// failed native validation, refused admission or transport uncertainty.
    pub fn into_conformance_node(
        self,
        graph: &crate::node_admission::ConformanceGraph,
    ) -> Result<super::CnpSemanticConformanceNode, CnpSemanticAdmissionFailure> {
        let checked = (|| {
            self.reauthenticate()?;
            graph.reauthenticate().map_err(unknown)?;
            let native = self.guard.custody().map_err(unknown)?;
            if !native
                .collection_plan
                .as_ref()
                .is_some_and(|plan| plan.same_original(graph.plan()))
            {
                return Err(refused("collection graph belongs to another original plan"));
            }
            self.guard
                .custody()
                .map_err(unknown)?
                .conformance
                .as_ref()
                .ok_or_else(|| refused("conformance node requires installed fixture custody"))?
                .authenticate_graph(self.scope()?, graph)
        })();
        if let Err(error) = checked {
            return Err(CnpSemanticAdmissionFailure {
                error,
                preparation: Box::new(self),
            });
        }
        self.into_node_installed(&graph.graph)
            .map(super::CnpSemanticConformanceNode)
    }

    fn into_node_installed(
        mut self,
        graph: &AdmittedGraph,
    ) -> Result<CnpSemanticNode, CnpSemanticAdmissionFailure> {
        let result = (|| {
            self.reauthenticate()?;
            let scope = self.scope()?;
            let install = scope.installation;
            if graph.world_binding_hash() != &install.world_binding_hash
                || graph.descriptor(&install.descriptor.id) != Some(&install.descriptor)
                || graph.binding(&install.descriptor.id) != Some(&install.binding)
                || graph.owner(&install.owner.owner.id) != Some(&install.owner)
            {
                return Err(refused(
                    "generic common admission differs from installed actual realization",
                ));
            }
            let mut state = SemanticRuntimeCustody::default();
            state
                .credit
                .reserve(&install.binding, install.maximum_semantic_bytes)?;
            state
                .credit
                .reserve(&install.owner, install.maximum_semantic_bytes)?;
            // Cleanup metadata is reserved before Admit or any activation effect.
            // Exhausted later semantic credit must not obstruct original release.
            state
                .credit
                .reserve_bytes(install.maximum_result_bytes, install.maximum_semantic_bytes)?;
            let route = NodeRoute {
                node: install.descriptor.id.clone(),
                owners: vec![OwnerIdentity {
                    owner: install.owner.owner.id.clone(),
                    incarnation: install.binding.authority.incarnation_id.clone(),
                    generation: install.binding.authority.owner_generation,
                }],
            };
            let request = AdmitRequest {
                bindings: vec![install.binding.clone()],
                world_binding_hash: install.world_binding_hash.clone(),
                admission_receipt: install.admission_receipt.clone(),
                extensions: Extensions::new(),
            };
            state
                .credit
                .reserve(&request, install.maximum_semantic_bytes)?;
            let expected = install.binding.identity().map_err(unknown)?;
            let expected_admission = install.admission.clone();
            let id = request_id("admit", &install.realize.realization_id)?;
            let native = self
                .guard
                .custody
                .as_mut()
                .ok_or_else(|| refused("generic original native custody is absent"))?;
            if native.runtime.is_some() {
                return Err(refused(
                    "generic original admission has already been reserved",
                ));
            }
            native
                .source
                .as_ref()
                .ok_or_else(|| refused("generic source admission policy is absent"))?
                .preflight_transition(native, super::CnpSemanticTransition::Admission)?;
            // The reserved native capsule owns bookkeeping before the first
            // remote admission effect, including failure or caller unwind.
            native.runtime = Some(state);
            self.authenticate_native_dispatch()?;
            let native = self
                .guard
                .custody
                .as_mut()
                .ok_or_else(|| refused("generic original native custody is absent"))?;
            let owner = Rc::clone(&native.read_owner);
            let call = super::process::ReadCall::begin(owner).map_err(unknown)?;
            let response = native
                .controller
                .as_mut()
                .ok_or_else(|| refused("generic original controller is absent"))?
                .call(id, None, Method::Admit, false, request)
                .map_err(unknown);
            call.finish(response.is_ok());
            let response = response?;
            let Some(MethodResult::Admit(admitted)) = response.result else {
                return Err(unknown("generic original admission did not complete"));
            };
            if admitted.admission_id != expected_admission
                || admitted.accepted_binding_hashes != [expected]
            {
                return Err(unknown(
                    "generic original admission changed the complete native binding",
                ));
            }
            self.reauthenticate()?;
            Ok(route)
        })();
        match result {
            Ok(route) => {
                let exact_profile = self
                    .guard
                    .custody
                    .as_ref()
                    .and_then(|native| native.source.as_ref())
                    .map(|source| source.installation().exact_facet.id.clone());
                let Some(exact_profile) = exact_profile else {
                    return Err(CnpSemanticAdmissionFailure {
                        error: unknown("generic installed profile disappeared"),
                        preparation: Box::new(self),
                    });
                };
                Ok(CnpSemanticNode {
                    preparation: Box::new(self),
                    route,
                    exact_profile,
                    affinity: ThreadAffinity::OwnerThread(std::thread::current().id()),
                })
            }
            Err(error) => Err(CnpSemanticAdmissionFailure {
                error,
                preparation: Box::new(self),
            }),
        }
    }
}

impl CnpSemanticNode {
    pub(super) fn source(&self) -> Result<Rc<dyn CnpSemanticSource>, OperationFailure> {
        self.preparation
            .guard
            .custody()
            .map_err(unknown)?
            .source
            .as_ref()
            .cloned()
            .ok_or_else(|| refused("generic installed native source is absent"))
    }

    pub(super) fn scope(&self) -> Result<CnpSemanticRealizationScope<'_>, OperationFailure> {
        self.preparation.scope()
    }

    pub(super) fn current(&self) -> Result<(), OperationFailure> {
        if !self.affinity.permits_current_thread() {
            return Err(refused(
                "generic native callback is on a foreign owner thread",
            ));
        }
        if self.state()?.quarantined {
            return Err(refused("generic original semantic custody is quarantined"));
        }
        self.preparation.reauthenticate()
    }

    pub(super) fn state(&self) -> Result<&SemanticRuntimeCustody, OperationFailure> {
        self.preparation
            .guard
            .custody()
            .map_err(unknown)?
            .runtime
            .as_ref()
            .ok_or_else(|| refused("generic original runtime custody is absent"))
    }

    pub(super) fn state_mut(&mut self) -> Result<&mut SemanticRuntimeCustody, OperationFailure> {
        self.preparation
            .guard
            .custody
            .as_mut()
            .and_then(|native| native.runtime.as_mut())
            .ok_or_else(|| refused("generic original runtime custody is absent"))
    }

    pub(super) fn controller_mut(&mut self) -> Result<&mut CnpController, OperationFailure> {
        self.preparation
            .guard
            .custody
            .as_mut()
            .and_then(|native| native.controller.as_mut())
            .ok_or_else(|| refused("generic original controller is absent"))
    }

    pub(super) fn call<T: serde::Serialize>(
        &mut self,
        request: Id,
        operation: Option<Id>,
        method: Method,
        owner_scoped: bool,
        body: T,
    ) -> Result<ResponseBody, OperationFailure> {
        self.preparation.authenticate_native_dispatch()?;
        let owner = Rc::clone(
            &self
                .preparation
                .guard
                .custody()
                .map_err(unknown)?
                .read_owner,
        );
        let call = super::process::ReadCall::begin(owner).map_err(unknown)?;
        let result = self
            .controller_mut()?
            .call(request, operation, method, owner_scoped, body)
            .map_err(unknown);
        // Successful per-operation retirement/consumed ACK preserves the owner.
        // Uncertain transport and unwind revoke the same original token.
        call.finish(result.is_ok());
        result
    }

    pub(super) fn upload(
        &mut self,
        reference: &crucible_node_contract::ContentRef,
        bytes: &[u8],
    ) -> Result<(), OperationFailure> {
        self.preparation.authenticate_native_dispatch()?;
        let owner = Rc::clone(
            &self
                .preparation
                .guard
                .custody()
                .map_err(unknown)?
                .read_owner,
        );
        let call = super::process::ReadCall::begin(owner).map_err(unknown)?;
        let result = self
            .controller_mut()?
            .upload(reference, bytes)
            .map_err(unknown);
        call.finish(result.is_ok());
        result
    }

    pub(super) fn maximum_bytes(&self) -> Result<usize, OperationFailure> {
        Ok(self.scope()?.installation.maximum_semantic_bytes)
    }
}
