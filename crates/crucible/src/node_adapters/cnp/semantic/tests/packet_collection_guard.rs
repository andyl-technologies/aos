//! Actual original-peer refusal before realization after collection-plan revocation.
//!
//! The small plan documents isolate the current-plan trust seam. They are not
//! normative population evidence, an accepted class, or common Ready authority.

#![cfg(test)]

use super::*;
use crate::node_admission::{
    AdmissionEvidence, ConformanceAdmissionAuthority, ConformancePlanEvidence, EvidenceError,
    InstalledConformancePlan, QualificationClaim,
};

struct CollectionAuthority {
    installation: HashRef,
    world: HashRef,
    source: ContentRef,
    plan: Vec<u8>,
    refused: Vec<u8>,
    current: Cell<bool>,
    installation_calls: Cell<usize>,
}

fn unavailable() -> EvidenceError {
    EvidenceError {
        message: "collection mechanism fixture is not ordinary qualification".into(),
    }
}

impl AdmissionEvidence for CollectionAuthority {
    fn content(&self, _: &ContentRef, _: usize) -> Result<Vec<u8>, EvidenceError> {
        Err(unavailable())
    }

    fn authenticate_implementation(&self, _: &ImplementationIdentity) -> Result<(), EvidenceError> {
        Err(unavailable())
    }

    fn authenticate_authority(&self, _: &NodeBinding) -> Result<(), EvidenceError> {
        Err(unavailable())
    }

    fn authenticate_schema(&self, _: &SchemaRef) -> Result<(), EvidenceError> {
        Err(unavailable())
    }

    fn qualify(&self, _: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        Err(unavailable())
    }
}

impl ConformanceAdmissionAuthority for CollectionAuthority {
    fn authenticate_collection_plan(
        &self,
        evidence: ConformancePlanEvidence<'_>,
    ) -> Result<(), EvidenceError> {
        if !self.current.get()
            || evidence.world != &self.world
            || evidence.plan_bytes != self.plan
            || evidence.refused_bytes != self.refused
            || evidence.sources != std::slice::from_ref(&self.source)
        {
            return Err(EvidenceError {
                message: "original collection plan revoked or changed".into(),
            });
        }
        Ok(())
    }
}

impl CnpSemanticConformanceAuthority for CollectionAuthority {
    fn authenticate_installation(
        &self,
        selection: &CnpSemanticInstallation,
    ) -> Result<(), OperationFailure> {
        self.installation_calls
            .set(self.installation_calls.get() + 1);
        if registry::installation_identity(selection)? != self.installation {
            return Err(refused("original collection fixture installation changed"));
        }
        // Deliberately independent of current: this callback remains authorized
        // while the complete original plan is revoked after registry enrollment.
        Ok(())
    }
}

#[test]
fn revoked_plan_after_registry_refuses_before_original_native_requests() {
    let mut fixture = Fixture::new(false, true);
    let authority = Rc::new(CollectionAuthority {
        installation: registry::installation_identity(&fixture.definition.installation).unwrap(),
        world: fixture.definition.installation.world_binding_hash.clone(),
        source: fixture.definition.installation.descriptor.model_ref.clone(),
        plan: bytes(json!({"scope": "current-plan-guard-mechanism", "cases": "not-executed"})),
        refused: bytes(json!({"decision": "refused", "missing": "complete normative evidence"})),
        current: Cell::new(true),
        installation_calls: Cell::new(0),
    });
    let plan = InstalledConformancePlan::install(
        ConformancePlanEvidence {
            plan_ref: &reference(&authority.plan),
            plan_bytes: &authority.plan,
            refused_ref: &reference(&authority.refused),
            refused_bytes: &authority.refused,
            world: &authority.world,
            sources: std::slice::from_ref(&authority.source),
        },
        authority.clone(),
    )
    .unwrap();
    let installed = fixture
        .registry
        .install_for_conformance(fixture.source.clone(), authority.clone(), &plan)
        .unwrap();
    let guard = fixture.launch_guard();
    let original_pid = guard.custody().unwrap().provider_pid();
    let received_before = guard
        .custody()
        .unwrap()
        .controller()
        .unwrap()
        .originals()
        .count();
    authority.current.set(false);
    authority
        .authenticate_installation(&fixture.definition.installation)
        .unwrap();
    let installation_calls = authority.installation_calls.get();

    let failure = CnpSemanticPreparation::prepare_for_conformance(guard, installed)
        .err()
        .unwrap();

    assert!(
        failure
            .error
            .reason
            .contains("original collection plan revoked")
    );
    assert_eq!(authority.installation_calls.get(), installation_calls);
    assert_eq!(fixture.source.gate_checks.get(), 0);
    assert_eq!(fixture.acceptance.calls.get(), 0);
    let original = failure.guard.custody().unwrap();
    assert_eq!(original.provider_pid(), original_pid);
    let controller = original.controller().unwrap();
    assert_eq!(controller.originals().count(), received_before);
    for operation in [
        "cnp-discover-packet-realization",
        "cnp-realize-packet-realization",
        "cnp-admit-packet-realization",
    ] {
        assert!(controller.original(&id(operation)).is_none());
    }

    drop(failure);
    assert_eq!(fixture.retained.borrow().len(), 1);
    assert_eq!(fixture.retained.borrow()[0].provider_pid(), original_pid);
}
