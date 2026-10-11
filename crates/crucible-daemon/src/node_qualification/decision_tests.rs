//! Exercises retained decisions and actual common admission delegation using models.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- These model fixtures panic when a claimed acceptance invariant fails.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible::node_admission::{
    AdmissionEvidence, EvidenceError, QualificationClaim as AdmissionClaim,
};
use crucible_node_contract::{
    BindingCompatibility, Extensions, Id, ImplementationIdentity, NodeBinding, OperatingContract,
    OperatingMode, OwnerRef, SchedulingRole, SchemaRef, U64,
};

fn evaluate(fixture: &Fixture) -> EvaluatedAcceptance<'_> {
    evaluate_acceptance(
        &fixture.bytes,
        &fixture.reference,
        &fixture.claim.unit,
        &fixture.claim.classes,
        &fixture.authority,
        AcceptanceLimits::default(),
    )
    .unwrap()
}

#[test]
fn refused_audits_retain_missing_failed_unexecuted_and_original_bytes() {
    for disposition in [
        RequirementDisposition::Failed,
        RequirementDisposition::Unsupported,
        RequirementDisposition::NotExecuted,
    ] {
        let mut fixture = Fixture::new();
        fixture.claim.requirements[0].disposition = disposition;
        fixture.claim.requirements[0].cases[0].verdict = CaseVerdict::Failed;
        let omitted = fixture.claim.requirements.remove(1).requirement;
        fixture.encode_changed_original();

        let evaluated = evaluate(&fixture);
        assert_eq!(evaluated.original_bytes(), fixture.bytes);
        assert_eq!(evaluated.record().original, fixture.claim);
        assert!(evaluated.record().missing_requirements.contains(&omitted));
        assert!(matches!(
            evaluated.record().decision,
            AcceptanceDecision::Refused { .. }
        ));
        let encoded = evaluated.record().canonical_bytes(8 * 1024 * 1024).unwrap();
        assert_eq!(
            AcceptanceRecord::from_json(&encoded, encoded.len()).unwrap(),
            *evaluated.record()
        );
        assert!(AcceptanceRecord::from_json(&encoded, encoded.len() - 1).is_err());
    }
}

#[test]
fn decoded_passed_data_cannot_override_native_kind_na_or_original_failure() {
    for change in 0..4 {
        let mut fixture = Fixture::new();
        match change {
            0 => fixture.claim.requirements[0].cases[0].kind = CaseKind::Model,
            1 => fixture.claim.requirements[0].cases[0].kind = CaseKind::IndependentProtocol,
            2 => fixture.claim.requirements[0].cases[0].verdict = CaseVerdict::Failed,
            _ => {
                fixture.claim.requirements[1].not_applicable_reason =
                    Some("vendor selected exclusion".into())
            }
        }
        fixture.encode_changed_original();
        assert!(matches!(
            evaluate(&fixture).record().decision,
            AcceptanceDecision::Refused { .. }
        ));
    }
}

#[test]
fn audit_limits_apply_before_evidence_or_canonical_report_allocation() {
    let fixture = Fixture::new();
    let limits = AcceptanceLimits {
        qualification: QualificationLimits {
            maximum_claim_bytes: fixture.bytes.len() - 1,
            ..QualificationLimits::default()
        },
        ..AcceptanceLimits::default()
    };
    assert!(
        evaluate_acceptance(
            &fixture.bytes,
            &fixture.reference,
            &fixture.claim.unit,
            &fixture.claim.classes,
            &fixture.authority,
            limits
        )
        .is_err()
    );
    assert_eq!(fixture.authority.case_calls.get(), 0);
    let evaluated = evaluate(&fixture);
    assert!(evaluated.record().canonical_bytes(1).is_err());
}

struct Policy {
    fixture: Fixture,
    record: AcceptanceRecord,
    binding: BindingCompatibility,
    required_classes: BTreeSet<QualificationClass>,
    changed_unit: bool,
    reject_now: Cell<bool>,
}

impl Policy {
    fn new() -> Self {
        let fixture = Fixture::new();
        let bytes = evaluate(&fixture)
            .record()
            .canonical_bytes(8 * 1024 * 1024)
            .unwrap();
        let record = AcceptanceRecord::from_json(&bytes, bytes.len()).unwrap();
        let reference = fixture.reference.clone();
        let id = |value| Id::new(value).unwrap();
        let owner = OwnerRef {
            id: id("owner"),
            participant_ids: vec![id("node")],
            state_domain_ids: vec![id("cpu")],
        };
        let binding = BindingCompatibility {
            schema_version: 1,
            node_id: id("node"),
            descriptor_hash: canonical::json_hash(
                "cnp.node-descriptor.v1",
                &serde_json::json!({"id":"node"}),
            )
            .unwrap(),
            implementation: ImplementationIdentity {
                schema_version: 1,
                implementation_id: id("model/1"),
                artifacts: vec![],
                model_definitions: vec![],
                formats: vec![],
                extensions: Extensions::new(),
            },
            profile_ref: reference.clone(),
            configuration_ref: reference.clone(),
            operating_contract: OperatingContract {
                schema_version: 1,
                mode: OperatingMode::Exact,
                scheduling_role: SchedulingRole::Active,
                ordering_profile: "superdense-v1".into(),
                policy_ref: reference.clone(),
                resolution_ps: Some(U64::new(50)),
                phase_ps: Some(U64::new(0)),
                facets: vec![],
                extensions: Extensions::new(),
            },
            execution_owner: owner.clone(),
            capture_owner: owner,
            capabilities_ref: reference.clone(),
            guarantees_ref: reference.clone(),
            qualification_refs: vec![reference],
            extensions: Extensions::new(),
        };
        let required_classes = fixture.claim.classes.clone();
        Self {
            required_classes,
            fixture,
            record,
            binding,
            changed_unit: false,
            reject_now: Cell::new(false),
        }
    }
}

impl InstalledQualificationAuthority for Policy {
    fn authenticate_claim(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        claim: &QualificationClaim,
    ) -> Result<(), QualificationError> {
        self.fixture
            .authority
            .authenticate_claim(reference, bytes, claim)
    }
    fn applicability(
        &self,
        unit: &QualificationUnit,
        classes: &BTreeSet<QualificationClass>,
        policy: &ContentRef,
    ) -> Result<BTreeMap<String, Applicability>, QualificationError> {
        self.fixture.authority.applicability(unit, classes, policy)
    }
    fn verify_evidence(
        &self,
        reference: &ContentRef,
        maximum: u64,
        dependencies: usize,
    ) -> Result<Vec<ContentRef>, QualificationError> {
        self.fixture
            .authority
            .verify_evidence(reference, maximum, dependencies)
    }
    fn authenticate_case(
        &self,
        unit: &QualificationUnit,
        requirement: &str,
        case: &CaseEvidence,
    ) -> Result<(), QualificationError> {
        if self.reject_now.get() {
            return Err(QualificationError::Refused(
                "original oracle no longer authenticated",
            ));
        }
        self.fixture
            .authority
            .authenticate_case(unit, requirement, case)
    }
}

impl InstalledAcceptancePolicy for Policy {
    fn scope_for_node(&self, node: &Id) -> Result<AcceptanceScope<'_>, QualificationError> {
        if node != &self.binding.node_id {
            return Err(QualificationError::Refused("unknown current node"));
        }
        let mut current_unit = self.fixture.claim.unit.clone();
        if self.changed_unit {
            current_unit.harness = self.fixture.reference.clone();
        }
        Ok(AcceptanceScope {
            binding: &self.binding,
            current_unit,
            required_classes: self.required_classes.clone(),
            original_bytes: &self.fixture.bytes,
            original_claim: &self.fixture.reference,
            record: &self.record,
        })
    }
}

#[derive(Default)]
struct Delegate {
    calls: Cell<usize>,
}
impl AdmissionEvidence for Delegate {
    fn content(&self, _: &ContentRef, _: usize) -> Result<Vec<u8>, EvidenceError> {
        Ok(vec![])
    }
    fn authenticate_implementation(&self, _: &ImplementationIdentity) -> Result<(), EvidenceError> {
        Ok(())
    }
    fn authenticate_authority(&self, _: &NodeBinding) -> Result<(), EvidenceError> {
        Ok(())
    }
    fn authenticate_schema(&self, _: &SchemaRef) -> Result<(), EvidenceError> {
        Ok(())
    }
    fn qualify(&self, _: AdmissionClaim<'_>) -> Result<(), EvidenceError> {
        self.calls.set(self.calls.get() + 1);
        Ok(())
    }
}

fn admit(
    policy: &Policy,
    delegate: &Delegate,
    binding: &BindingCompatibility,
) -> Result<(), EvidenceError> {
    BehavioralAdmissionEvidence::new(delegate, policy, AcceptanceLimits::default()).qualify(
        AdmissionClaim::Node {
            binding,
            binding_hash: &binding.identity().unwrap(),
            qualification_refs: &binding.qualification_refs,
        },
    )
}

#[test]
fn actual_node_admission_reauthenticates_before_delegation_and_preserves_other_routes() {
    let policy = Policy::new();
    let delegate = Delegate::default();
    admit(&policy, &delegate, &policy.binding).unwrap();
    assert_eq!(delegate.calls.get(), 1);
    policy.reject_now.set(true);
    assert!(admit(&policy, &delegate, &policy.binding).is_err());
    assert_eq!(delegate.calls.get(), 1);
    let adapter = BehavioralAdmissionEvidence::new(&delegate, &policy, AcceptanceLimits::default());
    adapter
        .qualify(AdmissionClaim::Coordinator {
            world_binding_hash: &policy.binding.identity().unwrap(),
            policy_ref: &policy.fixture.reference,
        })
        .unwrap();
    assert_eq!(delegate.calls.get(), 2);
}

#[test]
fn forged_stale_changed_class_or_reduced_scope_records_refuse_before_delegate() {
    for change in 0..6 {
        let mut policy = Policy::new();
        let mut candidate = policy.binding.clone();
        match change {
            0 => policy.changed_unit = true,
            1 => {
                policy
                    .record
                    .required_classes
                    .remove(&QualificationClass::ExactTiming);
            }
            2 => policy.record.original.requirements[0].cases[0].verdict = CaseVerdict::Failed,
            3 => candidate.configuration_ref = policy.fixture.claim.unit.harness.clone(),
            4 => candidate.qualification_refs.clear(),
            _ => policy.record.original_claim = policy.fixture.claim.unit.harness.clone(),
        }
        let delegate = Delegate::default();
        assert!(
            admit(&policy, &delegate, &candidate).is_err(),
            "change {change}"
        );
        assert_eq!(delegate.calls.get(), 0);
    }
}

#[test]
fn vendor_reduced_classes_cannot_reduce_actual_host_requirements() {
    let mut policy = Policy::new();
    policy
        .fixture
        .claim
        .classes
        .remove(&QualificationClass::ExactTiming);
    policy.fixture.claim.requirements[0].cases[0]
        .classes
        .remove(&QualificationClass::ExactTiming);
    policy.fixture.encode_changed_original();
    // Forge historically accepted audit data over the newly reduced claim.
    // The installed current requirements remain independently Base + Exact.
    policy.record.original = policy.fixture.claim.clone();
    policy.record.original_claim = policy.fixture.reference.clone();
    policy.binding.qualification_refs = vec![policy.fixture.reference.clone()];
    let delegate = Delegate::default();
    assert!(admit(&policy, &delegate, &policy.binding).is_err());
    assert_eq!(delegate.calls.get(), 0);
}

#[test]
fn protocol_report_v1_bytes_and_pass_meaning_remain_independent() {
    use crucible_node_provider::conformance::{CheckDisposition, CheckResult, ConformanceReport};

    let identity = canonical::hash("cnp.blob.v1", b"protocol plan").unwrap();
    let report = ConformanceReport {
        schema_version: 1,
        harness: "independent-protocol-only".into(),
        harness_executable: None,
        plan_identity: identity.clone(),
        fixture: Id::new("fixture/1").unwrap(),
        endpoints: vec![],
        results: vec![CheckResult {
            case: Id::new("original/1").unwrap(),
            check: None,
            disposition: CheckDisposition::Passed,
            request_identity: None,
            response_identity: None,
            diagnostic: String::new(),
        }],
        missing_checks: BTreeSet::new(),
        protocol_only: true,
    };
    let original_wire = serde_json::json!({
        "schema_version":1,"harness":"independent-protocol-only","harness_executable":null,
        "plan_identity":identity,"fixture":"fixture/1","endpoints":[],
        "results":[{"case":"original/1","check":null,"disposition":"passed",
            "request_identity":null,"response_identity":null,"diagnostic":""}],
        "missing_checks":[],"protocol_only":true,
    });
    assert_eq!(
        report.canonical_bytes().unwrap(),
        canonical::canonical_json(&original_wire).unwrap()
    );
    assert!(report.passed());

    let mut fixture = Fixture::new();
    fixture.claim.requirements[0].cases[0].kind = CaseKind::IndependentProtocol;
    fixture.encode_changed_original();
    assert!(matches!(
        evaluate(&fixture).record().decision,
        AcceptanceDecision::Refused { .. }
    ));
}

#[test]
fn unavailable_or_forged_original_evidence_blocks_previously_accepted_admission() {
    for missing in [false, true] {
        let mut policy = Policy::new();
        let result = &policy.fixture.claim.requirements[0].cases[0].result;
        if missing {
            policy.fixture.authority.objects.remove(&result.hash.digest);
        } else {
            policy
                .fixture
                .authority
                .objects
                .get_mut(&result.hash.digest)
                .unwrap()
                .1
                .push(0);
        }
        let delegate = Delegate::default();
        assert!(admit(&policy, &delegate, &policy.binding).is_err());
        assert_eq!(delegate.calls.get(), 0);
    }
}

struct ControlDiagnosticAuthority<'a> {
    original: &'a Authority,
    calls: Cell<usize>,
}

impl InstalledQualificationAuthority for ControlDiagnosticAuthority<'_> {
    fn authenticate_claim(
        &self,
        _: &ContentRef,
        _: &[u8],
        _: &QualificationClaim,
    ) -> Result<(), QualificationError> {
        self.calls.set(self.calls.get() + 1);
        Err(QualificationError::Evidence("\0".repeat(4000)))
    }

    fn applicability(
        &self,
        unit: &QualificationUnit,
        classes: &BTreeSet<QualificationClass>,
        policy: &ContentRef,
    ) -> Result<BTreeMap<String, Applicability>, QualificationError> {
        self.original.applicability(unit, classes, policy)
    }

    fn verify_evidence(
        &self,
        reference: &ContentRef,
        maximum: u64,
        dependencies: usize,
    ) -> Result<Vec<ContentRef>, QualificationError> {
        self.original
            .verify_evidence(reference, maximum, dependencies)
    }

    fn authenticate_case(
        &self,
        unit: &QualificationUnit,
        requirement: &str,
        case: &CaseEvidence,
    ) -> Result<(), QualificationError> {
        self.original.authenticate_case(unit, requirement, case)
    }
}

#[test]
fn report_precredit_covers_escaped_diagnostics_before_callbacks() {
    let fixture = Fixture::new();
    let authority = ControlDiagnosticAuthority {
        original: &fixture.authority,
        calls: Cell::new(0),
    };
    let accepted = evaluate(&fixture);
    let accepted_bytes = accepted.record().canonical_bytes(8 * 1024 * 1024).unwrap();
    let limits = AcceptanceLimits {
        maximum_record_bytes: accepted_bytes.len() + 8192,
        ..AcceptanceLimits::default()
    };

    // The previous fixed allowance admitted this report, then discovered the
    // escaped control-byte expansion only after the authority had run.
    let refused = evaluate_acceptance(
        &fixture.bytes,
        &fixture.reference,
        &fixture.claim.unit,
        &fixture.claim.classes,
        &authority,
        limits,
    );

    assert!(refused.is_err());
    assert_eq!(authority.calls.get(), 0);
}

#[test]
fn bounded_control_diagnostic_preserves_the_exact_original_refusal() {
    let fixture = Fixture::new();
    let authority = ControlDiagnosticAuthority {
        original: &fixture.authority,
        calls: Cell::new(0),
    };

    let evaluated = evaluate_acceptance(
        &fixture.bytes,
        &fixture.reference,
        &fixture.claim.unit,
        &fixture.claim.classes,
        &authority,
        AcceptanceLimits::default(),
    )
    .unwrap();
    let encoded = evaluated.record().canonical_bytes(8 * 1024 * 1024).unwrap();

    assert_eq!(authority.calls.get(), 1);
    let AcceptanceDecision::Refused { diagnostic } = &evaluated.record().decision else {
        panic!("an original evidence refusal cannot become acceptance");
    };
    assert_eq!(diagnostic.matches('\0').count(), 4000);
    assert!(diagnostic.len() <= 4096);
    assert!(encoded.windows(6).filter(|row| *row == b"\\u0000").count() >= 4000);
    assert_eq!(
        AcceptanceRecord::from_json(&encoded, encoded.len()).unwrap(),
        *evaluated.record()
    );
    assert_eq!(evaluated.original_bytes(), fixture.bytes);
}

#[path = "cnp_tests.rs"]
mod cnp;
