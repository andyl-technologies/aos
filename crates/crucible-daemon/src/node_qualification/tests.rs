//! Adversarial ledger models; these cases do not qualify a native provider.

// crucible-lint: allow panic-shortcut -- These node qualification tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
};

use crucible_node_contract::{ContentRef, canonical};

use super::*;

struct Authority {
    claim: ContentRef,
    policy: BTreeMap<String, Applicability>,
    objects: BTreeMap<String, (ContentRef, Vec<u8>)>,
    dependencies: BTreeMap<String, Vec<ContentRef>>,
    case_calls: Cell<usize>,
    reject_case: bool,
}

impl InstalledQualificationAuthority for Authority {
    fn authenticate_claim(
        &self,
        reference: &ContentRef,
        _: &[u8],
        _: &QualificationClaim,
    ) -> Result<(), QualificationError> {
        if reference != &self.claim {
            return Err(QualificationError::Evidence(
                "untrusted original report".into(),
            ));
        }
        Ok(())
    }

    fn applicability(
        &self,
        _: &QualificationUnit,
        _: &BTreeSet<QualificationClass>,
        _: &ContentRef,
    ) -> Result<BTreeMap<String, Applicability>, QualificationError> {
        Ok(self.policy.clone())
    }

    fn verify_evidence(
        &self,
        reference: &ContentRef,
        maximum_bytes: u64,
        maximum_dependencies: usize,
    ) -> Result<Vec<ContentRef>, QualificationError> {
        let Some((expected, bytes)) = self.objects.get(&reference.hash.digest) else {
            return Err(QualificationError::Evidence(
                "missing original object".into(),
            ));
        };
        if expected != reference
            || reference.length.get() > maximum_bytes
            || canonical::content_ref(bytes, &reference.media_type)? != *reference
        {
            return Err(QualificationError::Evidence(
                "changed original evidence".into(),
            ));
        }
        let dependencies = self
            .dependencies
            .get(&reference.hash.digest)
            .cloned()
            .unwrap_or_default();
        if dependencies.len() > maximum_dependencies {
            return Err(QualificationError::Evidence(
                "bounded dependency refusal".into(),
            ));
        }
        Ok(dependencies)
    }

    fn authenticate_case(
        &self,
        _: &QualificationUnit,
        _: &str,
        _: &CaseEvidence,
    ) -> Result<(), QualificationError> {
        self.case_calls.set(self.case_calls.get() + 1);
        if self.reject_case {
            return Err(QualificationError::Evidence(
                "independent oracle refuses".into(),
            ));
        }
        Ok(())
    }
}

struct Fixture {
    claim: QualificationClaim,
    bytes: Vec<u8>,
    reference: ContentRef,
    authority: Authority,
}

impl Fixture {
    fn new() -> Self {
        let mut objects = BTreeMap::new();
        let mut put = |body: &[u8], media: &str| {
            let reference = canonical::content_ref(body, media).unwrap();
            objects.insert(
                reference.hash.digest.clone(),
                (reference.clone(), body.to_vec()),
            );
            reference
        };
        let scope = put(b"model unit identity", "text/plain");
        let policy_ref = put(b"independent fixed model applicability", "text/plain");
        let limitations = put(b"ledger model only; no native qualification", "text/plain");
        let result = put(b"original case model", "text/plain");
        let oracle = put(b"independent model oracle", "text/plain");
        let (catalog, ids) = requirement_catalog().unwrap();
        let catalog_object = put(include_bytes!("requirements.txt"), "text/plain");
        assert_eq!(catalog_object, catalog);
        let (specification, specification_bytes) = normative_specification().unwrap();
        assert_eq!(put(&specification_bytes, "application/json"), specification);
        let unit = QualificationUnit {
            implementation: scope.clone(),
            realization: scope.clone(),
            descriptors: scope.clone(),
            contracts: scope.clone(),
            port_profiles: scope.clone(),
            environment: scope.clone(),
            harness: scope.clone(),
            fixtures: scope.clone(),
            specification,
        };
        let classes = BTreeSet::from([
            QualificationClass::BaseProvider,
            QualificationClass::ExactTiming,
        ]);
        let mut policy = BTreeMap::new();
        let requirements = ids
            .into_iter()
            .enumerate()
            .map(|(index, id)| {
                let (disposition, cases, reason, applicability) = if index == 0 {
                    let case = CaseEvidence {
                        case: "model-original-case".into(),
                        // This test authority is synthetic. The production gate
                        // delegates native classification to installed evidence.
                        kind: CaseKind::RealizedProvider,
                        verdict: CaseVerdict::Passed,
                        classes: classes.clone(),
                        result: result.clone(),
                        oracle: oracle.clone(),
                    };
                    (
                        RequirementDisposition::Passed,
                        vec![case],
                        None,
                        Applicability::Applicable {
                            classes: classes.clone(),
                        },
                    )
                } else {
                    let reason = format!("model-policy-exclusion:{id}");
                    (
                        RequirementDisposition::NotApplicable,
                        Vec::new(),
                        Some(reason.clone()),
                        Applicability::NotApplicable { reason },
                    )
                };
                policy.insert(id.to_owned(), applicability);
                RequirementResult {
                    requirement: id.into(),
                    disposition,
                    cases,
                    not_applicable_reason: reason,
                }
            })
            .collect();
        let claim = QualificationClaim {
            format: "crucible.node-qualification".into(),
            version: 1,
            unit,
            classes,
            catalog,
            applicability_policy: policy_ref,
            requirements,
            supersedes: None,
            limitations,
        };
        let bytes = canonical::canonical_json(&serde_json::to_value(&claim).unwrap()).unwrap();
        let reference = canonical::content_ref(&bytes, "application/json").unwrap();
        objects.insert(
            reference.hash.digest.clone(),
            (reference.clone(), bytes.clone()),
        );
        let authority = Authority {
            claim: reference.clone(),
            policy,
            objects,
            dependencies: BTreeMap::new(),
            case_calls: Cell::new(0),
            reject_case: false,
        };
        Self {
            claim,
            bytes,
            reference,
            authority,
        }
    }

    fn encode_changed_original(&mut self) {
        self.bytes =
            canonical::canonical_json(&serde_json::to_value(&self.claim).unwrap()).unwrap();
        self.reference = canonical::content_ref(&self.bytes, "application/json").unwrap();
        self.authority.claim = self.reference.clone();
        self.authority.objects.insert(
            self.reference.hash.digest.clone(),
            (self.reference.clone(), self.bytes.clone()),
        );
    }

    fn accept(&self) -> Result<AcceptedQualification, QualificationError> {
        accept_claim(
            &self.bytes,
            &self.reference,
            &self.claim.unit,
            &self.claim.classes,
            &self.authority,
            QualificationLimits::default(),
        )
    }
}

#[test]
fn complete_catalog_and_exact_scope_model_gate_refuse_changed_axes() {
    assert_eq!(requirement_catalog().unwrap().1, catalog::normative_ids());
    let fixture = Fixture::new();
    let accepted = fixture.accept().unwrap();
    assert_eq!(accepted.claim(), &fixture.reference);
    accepted
        .require_scope(&fixture.claim.unit, &fixture.claim.classes)
        .unwrap();

    for axis in 0..9 {
        let mut changed = fixture.claim.unit.clone();
        let foreign =
            canonical::content_ref(b"foreign independently measured axis", "text/plain").unwrap();
        match axis {
            0 => changed.implementation = foreign,
            1 => changed.realization = foreign,
            2 => changed.descriptors = foreign,
            3 => changed.contracts = foreign,
            4 => changed.port_profiles = foreign,
            5 => changed.environment = foreign,
            6 => changed.harness = foreign,
            7 => changed.fixtures = foreign,
            _ => changed.specification = foreign,
        }
        assert!(
            accepted
                .require_scope(&changed, &fixture.claim.classes)
                .is_err()
        );
        assert!(
            accept_claim(
                &fixture.bytes,
                &fixture.reference,
                &changed,
                &fixture.claim.classes,
                &fixture.authority,
                QualificationLimits::default()
            )
            .is_err()
        );
    }
    assert!(
        accepted
            .require_scope(
                &fixture.claim.unit,
                &BTreeSet::from([QualificationClass::CaptureModeledDurable])
            )
            .is_err()
    );
}

#[test]
fn omitted_duplicate_unknown_and_unexecuted_obligations_never_pass() {
    for mutation in 0..6 {
        let mut fixture = Fixture::new();
        match mutation {
            0 => {
                fixture.claim.requirements.pop();
            }
            1 => {
                fixture.claim.requirements[1] = fixture.claim.requirements[0].clone();
            }
            2 => {
                fixture.claim.requirements[1].requirement = "CN-FOREIGN-1".into();
            }
            3 => {
                fixture.claim.requirements[0].disposition = RequirementDisposition::NotExecuted;
            }
            4 => {
                fixture.claim.requirements[0].cases.clear();
            }
            _ => {
                fixture.claim.requirements[0].cases[0].verdict = CaseVerdict::Failed;
            }
        }
        fixture.encode_changed_original();
        assert!(
            fixture.accept().is_err(),
            "accepted ledger mutation {mutation}"
        );
    }
}

#[test]
fn provider_selected_exclusions_and_protocol_only_classes_refuse() {
    for mutation in 0..5 {
        let mut fixture = Fixture::new();
        match mutation {
            0 => {
                fixture.claim.requirements[0].disposition = RequirementDisposition::NotApplicable;
                fixture.claim.requirements[0].cases.clear();
                fixture.claim.requirements[0].not_applicable_reason =
                    Some("provider lacks test".into());
            }
            1 => {
                fixture.claim.requirements[1].not_applicable_reason =
                    Some("provider override".into());
            }
            2 => {
                fixture
                    .authority
                    .policy
                    .remove(&fixture.claim.requirements[1].requirement);
            }
            3 => {
                fixture.claim.requirements[0].cases[0].kind = CaseKind::IndependentProtocol;
            }
            _ => {
                fixture.claim.requirements[0].cases[0].kind = CaseKind::Model;
            }
        }
        fixture.encode_changed_original();
        assert!(
            fixture.accept().is_err(),
            "accepted unsupported native class {mutation}"
        );
    }
}

#[test]
fn unavailable_corrupt_transitive_and_conflicting_evidence_refuse() {
    for mutation in 0..4 {
        let mut fixture = Fixture::new();
        let result = fixture.claim.requirements[0].cases[0].result.clone();
        match mutation {
            0 => {
                fixture.authority.objects.remove(&result.hash.digest);
            }
            1 => {
                fixture
                    .authority
                    .objects
                    .get_mut(&result.hash.digest)
                    .unwrap()
                    .1
                    .push(1);
            }
            2 => {
                let missing =
                    canonical::content_ref(b"unavailable source dependency", "text/plain").unwrap();
                fixture
                    .authority
                    .dependencies
                    .insert(result.hash.digest.clone(), vec![missing]);
            }
            _ => {
                let mut changed = result.clone();
                changed.media_type = "application/json".into();
                fixture
                    .authority
                    .dependencies
                    .insert(result.hash.digest.clone(), vec![changed]);
            }
        }
        assert!(
            fixture.accept().is_err(),
            "accepted unavailable closure {mutation}"
        );
    }
    let mut fixture = Fixture::new();
    fixture.authority.reject_case = true;
    assert!(fixture.accept().is_err());
}

#[test]
fn prerequisites_case_populations_and_budget_remain_independent() {
    let mut fixture = Fixture::new();
    fixture
        .claim
        .classes
        .insert(QualificationClass::BranchIsolated);
    fixture.encode_changed_original();
    assert!(fixture.accept().is_err());

    let fixture = Fixture::new();
    for limits in [
        QualificationLimits {
            maximum_claim_bytes: fixture.bytes.len() - 1,
            ..Default::default()
        },
        QualificationLimits {
            maximum_cases: 0,
            ..Default::default()
        },
        QualificationLimits {
            maximum_evidence_objects: 1,
            ..Default::default()
        },
        QualificationLimits {
            maximum_evidence_bytes: 1,
            ..Default::default()
        },
        QualificationLimits {
            maximum_total_evidence_bytes: 1,
            ..Default::default()
        },
    ] {
        assert!(
            accept_claim(
                &fixture.bytes,
                &fixture.reference,
                &fixture.claim.unit,
                &fixture.claim.classes,
                &fixture.authority,
                limits
            )
            .is_err()
        );
    }
}

#[test]
fn release_inventory_reuses_exact_gate_without_partial_success() {
    let fixture = Fixture::new();
    let profile = RequiredProfile {
        bytes: &fixture.bytes,
        claim: &fixture.reference,
        unit: &fixture.claim.unit,
        classes: &fixture.claim.classes,
    };
    assert_eq!(
        verify_release_inventory(
            &[profile],
            &fixture.authority,
            QualificationLimits::default()
        )
        .unwrap()
        .len(),
        1
    );
    assert!(
        verify_release_inventory(&[], &fixture.authority, QualificationLimits::default()).is_err()
    );

    let mut foreign = fixture.claim.unit.clone();
    foreign.environment =
        canonical::content_ref(b"foreign release environment", "text/plain").unwrap();
    let profiles = [
        RequiredProfile {
            bytes: &fixture.bytes,
            claim: &fixture.reference,
            unit: &fixture.claim.unit,
            classes: &fixture.claim.classes,
        },
        RequiredProfile {
            bytes: &fixture.bytes,
            claim: &fixture.reference,
            unit: &foreign,
            classes: &fixture.claim.classes,
        },
    ];
    assert!(
        verify_release_inventory(
            &profiles,
            &fixture.authority,
            QualificationLimits::default()
        )
        .is_err()
    );
}
