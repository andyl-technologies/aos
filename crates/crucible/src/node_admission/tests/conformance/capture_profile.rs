//! Exercises dormant Capture dispatch without active or ordinary capture authority.

use super::*;

struct DefaultCaptureAuthority(Rc<Authority>);

impl AdmissionEvidence for DefaultCaptureAuthority {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, EvidenceError> {
        self.0.content(reference, maximum)
    }

    fn authenticate_implementation(
        &self,
        value: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        self.0.authenticate_implementation(value)
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        self.0.authenticate_authority(binding)
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        self.0.authenticate_schema(schema)
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        self.0.qualify(claim)
    }
}

impl ConformanceAdmissionAuthority for DefaultCaptureAuthority {
    fn authenticate_collection_plan(
        &self,
        plan: ConformancePlanEvidence<'_>,
    ) -> Result<(), EvidenceError> {
        self.0.authenticate_collection_plan(plan)
    }

    fn authenticate_collection_world(
        &self,
        plan: ConformancePlanEvidence<'_>,
        request: AdmissionRequest<'_>,
    ) -> Result<(), EvidenceError> {
        self.0.authenticate_collection_world(plan, request)
    }

    fn authenticate_collection_node(
        &self,
        plan: ConformancePlanEvidence<'_>,
        claim: QualificationClaim<'_>,
    ) -> Result<(), EvidenceError> {
        self.0.authenticate_collection_node(plan, claim)
    }

    fn authenticate_collection_current_scope(
        &self,
        plan: ConformancePlanEvidence<'_>,
        request: AdmissionRequest<'_>,
    ) -> Result<(), EvidenceError> {
        self.0.authenticate_collection_current_scope(plan, request)
    }
}

fn capture_claim<'a>(authority: &'a Authority, world: &'a HashRef) -> QualificationClaim<'a> {
    let owner = &authority.fixture.ownership.capture_owners[0];
    QualificationClaim::Capture {
        world_binding_hash: world,
        capture_owner_id: &owner.owner_id,
        procedure_ref: &owner.cut_procedure_ref,
    }
}

#[test]
fn default_capture_profile_refuses_even_when_ordinary_model_evidence_accepts() {
    let authority = Authority::new();
    let original_plan = authority.plan();
    let default_authority = Rc::new(DefaultCaptureAuthority(Rc::clone(&authority)));
    let plan =
        InstalledConformancePlan::install(original_plan.evidence(), default_authority).unwrap();
    let world = authority.fixture.world.identity().unwrap();

    assert!(authority.qualify(capture_claim(&authority, &world)).is_ok());
    let result = admit_conformance_graph(authority.request(), &plan, AdmissionLimits::default());

    assert!(result.is_err());
    assert_eq!(authority.capture_calls.get(), 0);
    // Only the explicit ordinary test call above was made. Collection must not
    // fall back to accepting ordinary evidence after its default refusal.
    assert_eq!(authority.ordinary_capture_calls.get(), 1);
}

#[test]
fn dormant_collection_capture_dispatch_is_separate_from_ordinary_capture() {
    let authority = Authority::new();
    let plan = authority.plan();

    let graph =
        admit_conformance_graph(authority.request(), &plan, AdmissionLimits::default()).unwrap();

    assert!(graph.graph.collecting);
    assert_eq!(
        authority.capture_calls.get(),
        authority.fixture.ownership.capture_owners.len()
    );
    assert_eq!(authority.ordinary_capture_calls.get(), 0);
    assert!(
        admit_graph(
            authority.request(),
            authority.as_ref(),
            AdmissionLimits::default()
        )
        .is_err()
    );
    assert_eq!(authority.ordinary_capture_calls.get(), 0);

    // This preexisting trusted model accepts ordinary Capture. The hook changes
    // neither that ordinary decision nor its dispatch route.
    let world = authority.fixture.world.identity().unwrap();
    assert!(authority.qualify(capture_claim(&authority, &world)).is_ok());
    assert_eq!(authority.ordinary_capture_calls.get(), 1);
    assert_eq!(
        authority.capture_calls.get(),
        authority.fixture.ownership.capture_owners.len()
    );
}

#[test]
fn dormant_collection_capture_refusal_is_not_replaced_by_ordinary_evidence() {
    let authority = Authority::new();
    let plan = authority.plan();
    authority.reject_capture.set(true);

    let result = admit_conformance_graph(authority.request(), &plan, AdmissionLimits::default());

    assert!(result.is_err());
    assert_eq!(authority.capture_calls.get(), 1);
    assert_eq!(authority.ordinary_capture_calls.get(), 0);
}

#[test]
fn dormant_capture_profile_rejects_wrong_claim_world_owner_and_procedure() {
    let authority = Authority::new();
    let plan = authority.plan();
    let world = authority.fixture.world.identity().unwrap();
    let owner = &authority.fixture.ownership.capture_owners[0];
    let foreign_world = canonical::json_hash("test/foreign-world", &"foreign").unwrap();
    let foreign_owner = id("owner/foreign");
    let foreign_procedure = canonical::content_ref(b"foreign", "text/plain").unwrap();
    let wrong_claim = QualificationClaim::CompleteInventory {
        world_binding_hash: &world,
        ownership_ref: &authority.fixture.world.ownership_ref,
        proof_ref: &authority.fixture.ownership.inventory_proof_ref,
    };

    for claim in [
        wrong_claim,
        QualificationClaim::Capture {
            world_binding_hash: &foreign_world,
            capture_owner_id: &owner.owner_id,
            procedure_ref: &owner.cut_procedure_ref,
        },
        QualificationClaim::Capture {
            world_binding_hash: &world,
            capture_owner_id: &foreign_owner,
            procedure_ref: &owner.cut_procedure_ref,
        },
        QualificationClaim::Capture {
            world_binding_hash: &world,
            capture_owner_id: &owner.owner_id,
            procedure_ref: &foreign_procedure,
        },
    ] {
        assert!(
            authority
                .authenticate_collection_capture_profile(plan.evidence(), claim)
                .is_err()
        );
    }
    assert!(
        authority
            .authenticate_collection_capture_profile(
                plan.evidence(),
                capture_claim(&authority, &world),
            )
            .is_ok()
    );
}

#[test]
fn dormant_capture_profile_reauthenticates_before_the_collection_hook() {
    let authority = Authority::new();
    let plan = authority.plan();
    let world = authority.fixture.world.identity().unwrap();
    authority.current.set(false);

    let result = admit_conformance_graph(authority.request(), &plan, AdmissionLimits::default());

    assert!(result.is_err());
    assert_eq!(authority.capture_calls.get(), 0);
    assert!(
        authority
            .authenticate_collection_capture_profile(
                plan.evidence(),
                capture_claim(&authority, &world),
            )
            .is_err()
    );
    assert_eq!(authority.capture_calls.get(), 0);
}

#[test]
fn successful_capture_hook_cannot_seal_a_revoked_original_plan() {
    let authority = Authority::new();
    let plan = authority.plan();
    authority.revoke_capture.set(true);

    let result = admit_conformance_graph(authority.request(), &plan, AdmissionLimits::default());

    assert!(result.is_err());
    assert_eq!(authority.capture_calls.get(), 1);
    assert_eq!(authority.ordinary_capture_calls.get(), 0);
    assert!(plan.reauthenticate().is_err());
}
