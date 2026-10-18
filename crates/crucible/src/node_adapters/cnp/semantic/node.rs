//! Owns generic original admission and the source-qualified common node capsule.

mod initial_preparation_storage;

mod construction_storage;
pub use construction_storage::CnpConformanceNodeConstructionStorageData;

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

impl CnpSemanticAdmissionFailure {
    /// Transfers actual native custody while retaining its exact admission refusal.
    ///
    /// # Panics
    /// The original trusted native supervisor must retain without unwinding.
    pub fn retire_original(&mut self) {
        self.preparation.retire_original();
    }
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
    // Selected same-holder conversion moves these genuine non-cloneable
    // witnesses with the controller before common runtime erases its node type.
    pub(super) retained_registry:
        Option<crucible_node_provider::handshake::OriginalExtensionRegistryOwner>,
    pub(super) retained_supervisor:
        Option<crucible_node_provider::connection::OriginalRetainedSupervisor>,
    pub(super) retained_operational:
        Option<std::rc::Rc<dyn crucible_node_provider::connection::ConnectionSupervisor>>,
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
        let checked = self.authenticate_original_conformance_graph(graph);
        if let Err(error) = checked {
            return Err(CnpSemanticAdmissionFailure {
                error,
                preparation: Box::new(self),
            });
        }
        self.into_node_installed(&graph.graph)
            .map(super::CnpSemanticConformanceNode)
    }

    fn authenticate_original_conformance_graph(
        &self,
        graph: &crate::node_admission::ConformanceGraph,
    ) -> Result<(), OperationFailure> {
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
    }

    fn prepare_original_node_installed(
        &mut self,
        graph: &AdmittedGraph,
    ) -> Result<(NodeRoute, Id), OperationFailure> {
        self.reauthenticate()?;
        let scope = self.scope()?;
        let install = scope.installation;
        // Retain the result metadata before completed-admission validation.
        // A Source getter after the terminal read could revoke that read.
        let exact_profile = install.exact_facet.id.clone();
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
        // Reusing a completed protocol Admit requires the graph, installation
        // and runtime-credit checks above, followed by the same terminal
        // native dispatch guard after all completed Source-pair validation.
        let reused = {
            let scope = self.scope()?;
            let mut slot = scope
                .native
                .completed_ack_admission
                .try_borrow_mut()
                .map_err(|_| refused("completed world admission slot is busy"))?;
            if let Some(original) = slot.as_mut() {
                original.consume(&self, &scope, &request)?;
                true
            } else if scope.native.completed_ack_protocol_started {
                return Err(refused(
                    "assigned ACK Admit requires its original world token",
                ));
            } else {
                self.authenticate_native_dispatch()?;
                false
            }
        };
        if !reused {
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
        }
        Ok((route, exact_profile))
    }

    fn into_node_installed(
        mut self,
        graph: &AdmittedGraph,
    ) -> Result<CnpSemanticNode, CnpSemanticAdmissionFailure> {
        let result = self.prepare_original_node_installed(graph);
        match result {
            Ok((route, exact_profile)) => Ok(CnpSemanticNode {
                preparation: Box::new(self),
                route,
                exact_profile,
                affinity: ThreadAffinity::OwnerThread(std::thread::current().id()),
                retained_registry: None,
                retained_supervisor: None,
                retained_operational: None,
            }),
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
        self.call_with_extensions(
            request,
            operation,
            method,
            owner_scoped,
            body,
            crucible_node_contract::Extensions::new(),
        )
    }

    pub(super) fn call_with_extensions<T: serde::Serialize>(
        &mut self,
        request: Id,
        operation: Option<Id>,
        method: Method,
        owner_scoped: bool,
        body: T,
        extensions: crucible_node_contract::Extensions,
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
            .call_with_extensions(request, operation, method, owner_scoped, body, extensions)
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

#[path = "node/restoration_construction.rs"]
mod restoration_construction;

/// Counts genuine installed-restoration node and activation custody as DATA.
pub use installed_restoration::OriginalInstalledRestorationCustodyConstructionData;
#[path = "node/installed_restoration.rs"]
pub(super) mod installed_restoration;

#[path = "node/restored_settled17.rs"]
mod restored_settled17;
pub(crate) use restored_settled17::{
    CnpRestoredNode17DecodeAttempt, CnpRestoredNode17DecodeConstructionData,
    CnpRestoredNode17ProducerAttemptBorrowedData, CnpRestoredNode17RawStorageData,
    CnpRestoredSettledValidatedNode17,
};

pub(crate) use installed_restoration::OriginalRestoredSettledNodeHistoryView;

pub(crate) use installed_restoration::original_restored_settled_semantic_history_counter_scratch_data;
