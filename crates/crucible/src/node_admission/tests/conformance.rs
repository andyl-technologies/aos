//! Models collection purpose, complete original scope and unchanged admission checks.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- These collection models panic when original scope or purpose invariants fail.
#![allow(clippy::unwrap_used)]

use super::*;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

struct Authority {
    fixture: Fixture,
    expected_plan: Vec<u8>,
    expected_audit: Vec<u8>,
    current: Cell<bool>,
    world_current: Cell<bool>,
    node_current: Cell<bool>,
    native_current: RefCell<Option<Rc<Cell<bool>>>>,
    revoke_operation_world: Cell<bool>,
    revoke_operation_node: Cell<bool>,
    revoke_operation_native: Cell<bool>,
    revoke_quantized_world: Cell<bool>,
    revoke_inputs_native: Cell<bool>,
    reject_nodes: Cell<bool>,
    revoke_last_node: Cell<bool>,
    revoke_operation: Cell<bool>,
    revoke_quantized: Cell<bool>,
    authorized_quantized: Cell<bool>,
    revoke_inputs: Cell<bool>,
    plan_calls: Cell<usize>,
    node_calls: Cell<usize>,
    dispatch: initial::dispatch::Probe,
}

impl Authority {
    fn new() -> Rc<Self> {
        let expected_plan = canonical::canonical_json(&serde_json::json!({
            "scope": "complete-model-population",
            "execution": "not-executed",
        }))
        .unwrap();
        let expected_audit = canonical::canonical_json(&serde_json::json!({
            "decision": "refused",
            "original_rows": ["not-executed"],
        }))
        .unwrap();

        Rc::new(Self {
            fixture: Fixture::new(),
            expected_plan,
            expected_audit,
            current: Cell::new(true),
            world_current: Cell::new(true),
            node_current: Cell::new(true),
            native_current: RefCell::new(None),
            revoke_operation_world: Cell::new(false),
            revoke_operation_node: Cell::new(false),
            revoke_operation_native: Cell::new(false),
            revoke_quantized_world: Cell::new(false),
            revoke_inputs_native: Cell::new(false),
            reject_nodes: Cell::new(false),
            revoke_last_node: Cell::new(false),
            revoke_operation: Cell::new(false),
            revoke_quantized: Cell::new(false),
            authorized_quantized: Cell::new(false),
            revoke_inputs: Cell::new(false),
            plan_calls: Cell::new(0),
            node_calls: Cell::new(0),
            dispatch: initial::dispatch::Probe::default(),
        })
    }

    fn request(&self) -> AdmissionRequest<'_> {
        AdmissionRequest {
            world: &self.fixture.world,
            descriptors: &self.fixture.descriptors,
            bindings: &self.fixture.bindings,
            owners: &self.fixture.owners,
            requirements: &self.fixture.requirements,
        }
    }

    fn plan(self: &Rc<Self>) -> InstalledConformancePlan {
        let plan_ref = canonical::content_ref(&self.expected_plan, "application/json").unwrap();
        let refused_ref = canonical::content_ref(&self.expected_audit, "application/json").unwrap();
        let world = self.fixture.world.identity().unwrap();
        InstalledConformancePlan::install(
            ConformancePlanEvidence {
                plan_ref: &plan_ref,
                plan_bytes: &self.expected_plan,
                refused_ref: &refused_ref,
                refused_bytes: &self.expected_audit,
                world: &world,
                sources: std::slice::from_ref(&self.fixture.world.initialization_ref),
            },
            self.clone(),
        )
        .unwrap()
    }
}

fn failure() -> EvidenceError {
    EvidenceError {
        message: "current installed model collection scope changed".into(),
    }
}

impl AdmissionEvidence for Authority {
    fn content(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, EvidenceError> {
        self.fixture.evidence.content(reference, maximum_bytes)
    }

    fn authenticate_implementation(
        &self,
        value: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        self.fixture.evidence.authenticate_implementation(value)
    }

    fn authenticate_authority(&self, value: &NodeBinding) -> Result<(), EvidenceError> {
        self.fixture.evidence.authenticate_authority(value)
    }

    fn authenticate_schema(&self, value: &SchemaRef) -> Result<(), EvidenceError> {
        self.fixture.evidence.authenticate_schema(value)
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        if matches!(claim, QualificationClaim::Node { .. }) {
            return Err(failure());
        }
        self.fixture.evidence.qualify(claim)
    }
}

impl ConformanceAdmissionAuthority for Authority {
    fn authenticate_collection_current_scope(
        &self,
        plan: ConformancePlanEvidence<'_>,
        request: AdmissionRequest<'_>,
    ) -> Result<(), EvidenceError> {
        // This model reads independent original revisions directly. It invokes
        // no callback; production authorities need source-owned native readers.
        if !self.current.get()
            || !self.world_current.get()
            || !self.node_current.get()
            || self
                .native_current
                .borrow()
                .as_ref()
                .is_some_and(|current| !current.get())
            || plan.plan_bytes != self.expected_plan
            || plan.refused_bytes != self.expected_audit
            || plan.world != &self.fixture.world.identity().unwrap()
            || plan.sources != [self.fixture.world.initialization_ref.clone()]
            || request.world != &self.fixture.world
            || request.descriptors != self.fixture.descriptors
            || request.bindings != self.fixture.bindings
            || request.owners != self.fixture.owners
        {
            return Err(failure());
        }
        Ok(())
    }

    fn authenticate_collection_quantized(
        &self,
        plan: ConformancePlanEvidence<'_>,
        request: AdmissionRequest<'_>,
    ) -> Result<(), EvidenceError> {
        if !self.authorized_quantized.get() {
            return Err(failure());
        }
        self.authenticate_collection_world(plan, request)?;
        if self.revoke_quantized.replace(false) {
            self.current.set(false);
        }
        if self.revoke_quantized_world.replace(false) {
            self.world_current.set(false);
        }
        Ok(())
    }

    fn authenticate_collection_inputs(
        &self,
        plan: ConformancePlanEvidence<'_>,
        batch: &crate::node_scheduling::RuntimeInputBatch,
    ) -> Result<(), EvidenceError> {
        self.authenticate_collection_plan(plan)?;
        if batch.stage_operation() != &id("original/model-stage")
            || batch.batch() != &id("original/model-batch")
            || !batch.deliveries().is_empty()
            || !batch.payloads().is_empty()
        {
            return Err(failure());
        }
        if self.revoke_inputs.replace(false) {
            self.current.set(false);
        }
        if self.revoke_inputs_native.replace(false) {
            self.native_current.borrow().as_ref().unwrap().set(false);
        }
        Ok(())
    }

    fn authenticate_collection_operation(
        &self,
        plan: ConformancePlanEvidence<'_>,
        node: &Id,
        operation: &Id,
        request: &crate::node_contract::OperationRequest,
    ) -> Result<(), EvidenceError> {
        self.authenticate_collection_plan(plan)?;
        if !self
            .fixture
            .descriptors
            .iter()
            .any(|selected| &selected.id == node)
            || operation != &id("original/model-case")
            || !matches!(
                request,
                crate::node_contract::OperationRequest::ExactRun { .. }
            ) && !(self.authorized_quantized.get()
                && matches!(
                    request,
                    crate::node_contract::OperationRequest::QuantumBegin { .. }
                ))
        {
            return Err(failure());
        }
        if self.revoke_operation.replace(false) {
            self.current.set(false);
        }
        if self.revoke_operation_world.replace(false) {
            self.world_current.set(false);
        }
        if self.revoke_operation_node.replace(false) {
            self.node_current.set(false);
        }
        if self.revoke_operation_native.replace(false) {
            self.native_current.borrow().as_ref().unwrap().set(false);
        }
        Ok(())
    }

    fn authenticate_collection_plan(
        &self,
        plan: ConformancePlanEvidence<'_>,
    ) -> Result<(), EvidenceError> {
        self.plan_calls.set(self.plan_calls.get() + 1);
        if !self.current.get()
            || plan.plan_bytes != self.expected_plan
            || plan.refused_bytes != self.expected_audit
            || plan.world != &self.fixture.world.identity().unwrap()
            || plan.sources != [self.fixture.world.initialization_ref.clone()]
        {
            return Err(failure());
        }
        Ok(())
    }

    fn authenticate_collection_world(
        &self,
        plan: ConformancePlanEvidence<'_>,
        request: AdmissionRequest<'_>,
    ) -> Result<(), EvidenceError> {
        self.authenticate_collection_plan(plan)?;
        if request.world != &self.fixture.world
            || request.descriptors != self.fixture.descriptors
            || request.bindings != self.fixture.bindings
            || request.owners != self.fixture.owners
            || canonical::canonical_json(&serde_json::to_value(request.requirements).unwrap())
                .unwrap()
                != canonical::canonical_json(
                    &serde_json::to_value(&self.fixture.requirements).unwrap(),
                )
                .unwrap()
        {
            return Err(failure());
        }
        Ok(())
    }

    fn authenticate_collection_node(
        &self,
        plan: ConformancePlanEvidence<'_>,
        claim: QualificationClaim<'_>,
    ) -> Result<(), EvidenceError> {
        self.authenticate_collection_plan(plan)?;
        self.node_calls.set(self.node_calls.get() + 1);
        let QualificationClaim::Node {
            binding,
            binding_hash,
            qualification_refs,
        } = claim
        else {
            return Err(failure());
        };
        if self.reject_nodes.get()
            || !self.fixture.bindings.iter().any(|selected| {
                &selected.compatibility == binding
                    && &selected.compatibility.identity().unwrap() == binding_hash
                    && selected.compatibility.qualification_refs == qualification_refs
            })
        {
            return Err(failure());
        }
        if self.revoke_last_node.get()
            && binding.node_id == self.fixture.bindings.last().unwrap().compatibility.node_id
        {
            self.revoke_last_node.set(false);
            self.current.set(false);
        }
        Ok(())
    }
}

#[test]
fn collecting_seal_cannot_supply_ordinary_node_qualification() {
    let authority = Authority::new();
    let plan = authority.plan();
    let collected =
        admit_conformance_graph(authority.request(), &plan, AdmissionLimits::default()).unwrap();

    assert!(collected.graph.collecting);
    assert_eq!(collected.world(), &authority.fixture.world);
    assert_eq!(authority.node_calls.get(), authority.fixture.bindings.len());
    assert!(
        admit_graph(
            authority.request(),
            authority.as_ref(),
            AdmissionLimits::default()
        )
        .is_err()
    );
}

#[test]
fn changed_plan_world_and_source_refuse_original_scope() {
    let authority = Authority::new();
    let plan = authority.plan();
    let mut world = authority.fixture.world.clone();
    world.initialization_ref = world.scenario_ref.clone();
    let mut request = authority.request();
    request.world = &world;
    assert!(admit_conformance_graph(request, &plan, AdmissionLimits::default()).is_err());

    let changed =
        canonical::canonical_json(&serde_json::json!({"scope":"different-plan"})).unwrap();
    let root = canonical::content_ref(&changed, "application/json").unwrap();
    assert!(
        InstalledConformancePlan::install(
            ConformancePlanEvidence {
                plan_ref: &root,
                plan_bytes: &changed,
                ..plan.evidence()
            },
            authority.clone()
        )
        .is_err()
    );
    assert!(
        InstalledConformancePlan::install(
            ConformancePlanEvidence {
                sources: std::slice::from_ref(&authority.fixture.world.scenario_ref),
                ..plan.evidence()
            },
            authority.clone()
        )
        .is_err()
    );
}

#[test]
fn revoked_plan_and_refused_node_never_gain_collection_seal() {
    let authority = Authority::new();
    let plan = authority.plan();
    authority.reject_nodes.set(true);
    assert!(
        admit_conformance_graph(authority.request(), &plan, AdmissionLimits::default()).is_err()
    );
    authority.reject_nodes.set(false);
    let graph =
        admit_conformance_graph(authority.request(), &plan, AdmissionLimits::default()).unwrap();

    authority.current.set(false);
    assert!(graph.reauthenticate().is_err());
    assert!(
        admit_conformance_graph(authority.request(), &plan, AdmissionLimits::default()).is_err()
    );
}

#[test]
fn collection_does_not_replace_schema_or_native_authority_checks() {
    let mut authority = Authority::new();
    Rc::get_mut(&mut authority)
        .unwrap()
        .fixture
        .evidence
        .reject_schema = true;
    let plan = authority.plan();
    assert!(
        admit_conformance_graph(authority.request(), &plan, AdmissionLimits::default()).is_err()
    );
    assert_eq!(authority.node_calls.get(), 0);

    let mut authority = Authority::new();
    Rc::get_mut(&mut authority)
        .unwrap()
        .fixture
        .evidence
        .reject_authority = true;
    let plan = authority.plan();
    assert!(
        admit_conformance_graph(authority.request(), &plan, AdmissionLimits::default()).is_err()
    );
}

#[test]
fn ordinary_runtime_refuses_private_collecting_purpose_before_readiness() {
    let authority = Authority::new();
    let plan = authority.plan();
    let collected =
        admit_conformance_graph(authority.request(), &plan, AdmissionLimits::default()).unwrap();
    let activation = crate::node_contract::ActivationRecord {
        generation: U64::new(1),
        activation_id: id("collected-original"),
        world_binding_hash: collected.graph.world_hash.clone(),
        owners: vec![],
        boundary: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
    };
    let failure = crate::node_contract::NodeRuntime::new(
        &collected.graph,
        vec![],
        activation,
        crate::node_contract::RuntimeLimits::default(),
        crate::node_contract::test_custody_slot(),
    )
    .err()
    .unwrap();
    assert_eq!(
        failure.error,
        crate::node_contract::RuntimeError::ForeignAuthority
    );
}

#[test]
fn direct_document_credit_refuses_before_authentication_or_copy() {
    let authority = Authority::new();
    let plan = authority.plan();
    let calls = authority.plan_calls.get();
    let oversized = vec![b' '; 8 * 1024 * 1024 + 1];
    let root = canonical::content_ref(&oversized, "application/json").unwrap();
    assert!(
        InstalledConformancePlan::install(
            ConformancePlanEvidence {
                plan_ref: &root,
                plan_bytes: &oversized,
                ..plan.evidence()
            },
            authority.clone()
        )
        .is_err()
    );
    assert_eq!(authority.plan_calls.get(), calls);
}

struct Uninstalled(Evidence);

impl AdmissionEvidence for Uninstalled {
    fn content(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, EvidenceError> {
        self.0.content(reference, maximum_bytes)
    }

    fn authenticate_implementation(
        &self,
        value: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        self.0.authenticate_implementation(value)
    }

    fn authenticate_authority(&self, value: &NodeBinding) -> Result<(), EvidenceError> {
        self.0.authenticate_authority(value)
    }

    fn authenticate_schema(&self, value: &SchemaRef) -> Result<(), EvidenceError> {
        self.0.authenticate_schema(value)
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        self.0.qualify(claim)
    }
}

impl ConformanceAdmissionAuthority for Uninstalled {}

#[test]
fn ordinary_evidence_cannot_install_collection_authority_by_default() {
    let authority = Authority::new();
    let plan = authority.plan();
    let uninstalled = Rc::new(Uninstalled(Evidence::default()));
    assert!(InstalledConformancePlan::install(plan.evidence(), uninstalled).is_err());
}

#[test]
fn input_collection_and_grants_require_separate_current_installed_authorization() {
    let authority = Authority::new();
    let plan = authority.plan();
    let graph =
        admit_conformance_graph(authority.request(), &plan, AdmissionLimits::default()).unwrap();
    assert!(graph.authenticate_quantized().is_err());
    assert!(
        graph
            .authenticate_operation(
                &authority.fixture.descriptors[0].id,
                &id("unauthorized-original"),
                &crate::node_contract::OperationRequest::Observe,
            )
            .is_err()
    );
    assert_eq!(
        authority.node_calls.get(),
        authority.fixture.bindings.len() * 3
    );
}

#[test]
fn serialized_world_data_does_not_erase_collection_authorization_requirement() {
    let authority = Authority::new();
    let plan = authority.plan();
    let graph =
        admit_conformance_graph(authority.request(), &plan, AdmissionLimits::default()).unwrap();
    let bytes = serde_json::to_vec(graph.world()).unwrap();
    let reopened: WorldBinding = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(reopened, authority.fixture.world);

    let request = AdmissionRequest {
        world: &reopened,
        ..authority.request()
    };
    assert!(admit_graph(request, authority.as_ref(), AdmissionLimits::default()).is_err());
}

#[test]
fn ordinary_prepared_nodes_cannot_be_coerced_into_collection_runtime() {
    let authority = Authority::new();
    let plan = authority.plan();
    let graph =
        admit_conformance_graph(authority.request(), &plan, AdmissionLimits::default()).unwrap();
    let prepared = crate::node_contract::PreparedRealization::new(
        crate::node_contract::test_nodes(&graph.graph),
        crate::node_contract::ActivationRecord {
            generation: U64::new(1),
            activation_id: id("wrong-original-native-purpose"),
            world_binding_hash: graph.world().identity().unwrap(),
            owners: vec![],
            boundary: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
        },
        crate::node_contract::RuntimeLimits::default(),
        crate::node_contract::test_custody_slot(),
    );
    let failure = crate::node_contract::ConformanceRuntime::from_prepared(graph, prepared)
        .err()
        .unwrap();
    assert!(failure.reason.contains("same original plan"));
    drop(failure);
}

#[path = "conformance_initial.rs"]
mod initial;

#[test]
fn quantized_case_revocation_cannot_return_current_collection_permission() {
    let authority = Authority::new();
    let plan = authority.plan();
    let graph =
        admit_conformance_graph(authority.request(), &plan, AdmissionLimits::default()).unwrap();
    authority.authorized_quantized.set(true);
    authority.revoke_quantized.set(true);

    assert!(graph.authenticate_quantized().is_err());
    assert!(!authority.current.get());
    assert!(graph.reauthenticate().is_err());
}

#[test]
fn quantized_world_revocation_refuses_with_original_plan_still_live() {
    let authority = Authority::new();
    let plan = authority.plan();
    let graph =
        admit_conformance_graph(authority.request(), &plan, AdmissionLimits::default()).unwrap();
    authority.authorized_quantized.set(true);
    authority.revoke_quantized_world.set(true);

    assert!(graph.authenticate_quantized().is_err());
    assert!(plan.reauthenticate().is_ok());
    assert!(!authority.world_current.get());
    assert!(graph.reauthenticate().is_err());
}

#[test]
fn final_collection_revision_authority_is_unavailable_by_default() {
    let authority = Authority::new();
    let plan = authority.plan();
    let uninstalled = Uninstalled(Evidence::default());

    assert!(
        uninstalled
            .authenticate_collection_current_scope(plan.evidence(), authority.request(),)
            .is_err()
    );
    assert!(plan.reauthenticate().is_ok());
}
