//! Exercises original-enrollment custody with explicitly unqualified model cases.
//!
//! No test authority below represents native evidence or an Accepted provider.
//! Every population deliberately retains missing mandatory model observations.

// crucible-lint: allow panic-shortcut -- Assertions identify model enrollment custody regressions.

use std::cell::{Cell, RefCell};

use super::*;
use crate::node_qualification::{
    CaseKind, CaseVerdict, InstalledWitnessAuthority, PlannedWitnessCase, QualificationLimits,
    RequirementDisposition, WitnessCriterion, WitnessPlan, WitnessPopulation,
    normative_specification, requirement_catalog,
};
use crucible_engine::node_contract::ProviderRegistryLimits;
use crucible_node_format::{ResourceLimits, U64, canonical};

struct ModelSource {
    plan: WitnessPlan,
    plan_reference: ContentRef,
    plan_bytes: Vec<u8>,
    claim_reference: ContentRef,
    claim_bytes: Vec<u8>,
    binding: BindingCompatibility,
    record: AcceptanceRecord,
    calls: Cell<usize>,
    source_inspection_action: Cell<u8>,
    panic_plan: bool,
    withdraw_on_plan: Cell<bool>,
    withdrawn: Cell<bool>,
    revision_to_revoke: RefCell<Option<Rc<InstalledProviderRevision>>>,
}

impl ModelSource {
    fn new(panic_plan: bool) -> Self {
        let axis = canonical::content_ref(b"unqualified enrollment model", "text/plain").unwrap();
        let unit = QualificationUnit {
            implementation: axis.clone(),
            realization: axis.clone(),
            descriptors: axis.clone(),
            contracts: axis.clone(),
            port_profiles: axis.clone(),
            environment: axis.clone(),
            harness: axis.clone(),
            fixtures: axis.clone(),
            specification: normative_specification().unwrap().0,
        };
        let plan = WitnessPlan {
            schema: "crucible.node-witness-plan.v1".into(),
            unit,
            classes: BTreeSet::from([QualificationClass::BaseProvider]),
            requirements: requirement_catalog()
                .unwrap()
                .1
                .into_iter()
                .map(|id| {
                    (
                        id.into(),
                        WitnessCriterion::Applicable {
                            cases: vec!["model/missing".into()],
                            criterion: axis.clone(),
                        },
                    )
                })
                .collect(),
            cases: vec![PlannedWitnessCase {
                id: "model/missing".into(),
                kind: CaseKind::Model,
                classes: BTreeSet::from([QualificationClass::BaseProvider]),
                oracle: axis.clone(),
            }],
            limitations: axis,
        };
        let plan_bytes = canonical::canonical_json(&serde_json::to_value(&plan).unwrap()).unwrap();
        let plan_reference = canonical::content_ref(&plan_bytes, "application/json").unwrap();
        struct PlanOnly;
        impl InstalledWitnessAuthority for PlanOnly {
            fn authenticate_plan(
                &self,
                _: &ContentRef,
                _: &[u8],
                _: &WitnessPlan,
            ) -> Result<(), QualificationError> {
                Ok(())
            }
            fn authenticate_result(
                &self,
                _: &WitnessPlan,
                _: &PlannedWitnessCase,
                _: CaseVerdict,
                _: &ContentRef,
                _: &[u8],
            ) -> Result<(), QualificationError> {
                Err(refused("no model observations installed"))
            }
        }
        let issued = WitnessPopulation::install(
            &plan_bytes,
            &plan_reference,
            &PlanOnly,
            QualificationLimits::default(),
        )
        .unwrap()
        .finish()
        .unwrap();
        let claim: QualificationClaim = serde_json::from_slice(issued.bytes()).unwrap();
        let (graph, _) = crucible_engine::node_admission::test_double_graph(false);
        let mut binding = graph
            .binding(graph.node_ids().next().unwrap())
            .unwrap()
            .compatibility
            .clone();
        binding.qualification_refs = vec![issued.reference().clone()];
        let record = AcceptanceRecord {
            format: "crucible.node-acceptance".into(),
            version: 1,
            original_claim: issued.reference().clone(),
            original: claim,
            evaluated_unit: plan.unit.clone(),
            required_classes: plan.classes.clone(),
            missing_requirements: BTreeSet::new(),
            decision: AcceptanceDecision::Refused {
                diagnostic: "missing original model cases".into(),
            },
        };
        Self {
            plan,
            plan_reference,
            plan_bytes,
            claim_reference: issued.reference().clone(),
            claim_bytes: issued.bytes().to_vec(),
            binding,
            record,
            calls: Cell::new(0),
            source_inspection_action: Cell::new(0),
            panic_plan,
            withdraw_on_plan: Cell::new(false),
            withdrawn: Cell::new(false),
            revision_to_revoke: RefCell::new(None),
        }
    }

    fn runner(&self) -> ProductionConformanceRunner<'_> {
        ProductionConformanceRunner::new(
            self,
            self.binding.node_id.clone(),
            self.binding.identity().unwrap(),
            &self.plan_bytes,
            &self.plan_reference,
            QualificationLimits::default(),
        )
        .unwrap()
    }
}

impl InstalledWitnessAuthority for ModelSource {
    fn authenticate_plan(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        plan: &WitnessPlan,
    ) -> Result<(), QualificationError> {
        if reference != &self.plan_reference || bytes != self.plan_bytes || plan != &self.plan {
            return Err(refused("model original plan differs"));
        }
        Ok(())
    }
    fn authenticate_result(
        &self,
        _: &WitnessPlan,
        _: &PlannedWitnessCase,
        _: CaseVerdict,
        _: &ContentRef,
        _: &[u8],
    ) -> Result<(), QualificationError> {
        Err(refused("no model original result"))
    }
}

impl InstalledQualificationAuthority for ModelSource {
    fn authenticate_claim(
        &self,
        _: &ContentRef,
        _: &[u8],
        _: &QualificationClaim,
    ) -> Result<(), QualificationError> {
        self.calls.set(self.calls.get() + 1);
        Err(refused("model cannot authenticate native coverage"))
    }
    fn applicability(
        &self,
        _: &QualificationUnit,
        classes: &BTreeSet<QualificationClass>,
        _: &ContentRef,
    ) -> Result<BTreeMap<String, Applicability>, QualificationError> {
        Ok(self
            .plan
            .requirements
            .keys()
            .map(|id| {
                (
                    id.clone(),
                    Applicability::Applicable {
                        classes: classes.clone(),
                    },
                )
            })
            .collect())
    }
    fn verify_evidence(
        &self,
        _: &ContentRef,
        _: u64,
        _: usize,
    ) -> Result<Vec<ContentRef>, QualificationError> {
        Err(refused("no model evidence closure"))
    }
    fn authenticate_case(
        &self,
        _: &QualificationUnit,
        _: &str,
        _: &CaseEvidence,
    ) -> Result<(), QualificationError> {
        Err(refused("no original model case"))
    }
}

impl InstalledAcceptancePolicy for ModelSource {
    fn scope_for_node(&self, node: &Id) -> Result<AcceptanceScope<'_>, QualificationError> {
        self.calls.set(self.calls.get() + 1);
        if self.withdrawn.get() || node != &self.binding.node_id {
            return Err(refused("foreign model node"));
        }
        Ok(AcceptanceScope {
            binding: &self.binding,
            current_unit: self.plan.unit.clone(),
            required_classes: self.plan.classes.clone(),
            original_bytes: &self.claim_bytes,
            original_claim: &self.claim_reference,
            record: &self.record,
        })
    }
}

impl InstalledConformanceAuthority for ModelSource {
    fn execute_original_source_inspection(
        &self,
        _: &WitnessPlan,
        _: &PlannedWitnessCase,
        output: &mut super::super::OriginalSourceInspectionSlot,
    ) -> Result<CaseVerdict, QualificationError> {
        self.calls.set(self.calls.get() + 1);
        output.write_original(br#"{"model":"unqualified source original"}"#)?;
        match self.source_inspection_action.get() {
            1 => Err(refused("modeled source refusal after original write")),
            2 => panic!("modeled source unwind after original write"),
            _ => Ok(CaseVerdict::Passed),
        }
    }

    fn authenticate_original_provider_plan(
        &self,
        _: ProviderPlanningRequest<'_>,
        _: &ProviderPreparationPlan,
    ) -> Result<(), QualificationError> {
        self.calls.set(self.calls.get() + 1);
        assert!(!self.panic_plan, "modeled installed source callback unwind");
        if let Some(revision) = self.revision_to_revoke.borrow_mut().take() {
            revision.revoke();
        }
        if self.withdraw_on_plan.get() {
            self.withdrawn.set(true);
        }
        Ok(())
    }
}

fn local(source: &ModelSource) -> (Id, Vec<Id>, ResourceLimits, ProviderPreparationPlan) {
    let (graph, _) = crucible_engine::node_admission::test_double_graph(false);
    let descriptor = graph.descriptor(&source.binding.node_id).unwrap().clone();
    let resources = ResourceLimits {
        cpu_budget_ns: U64::new(1),
        memory_bytes: U64::new(1),
        writable_bytes: U64::new(1),
        processes: U64::new(1),
        descriptors: U64::new(1),
        pending_events: U64::new(1),
        content_bytes: U64::new(1),
        maximum_operations: U64::new(1),
        extensions: BTreeMap::new(),
    };
    (
        Id::new("model/profile").unwrap(),
        vec![source.binding.node_id.clone()],
        resources,
        ProviderPreparationPlan {
            descriptors: vec![descriptor],
            bindings: vec![source.binding.clone()],
        },
    )
}

fn enroll(
    source: Rc<ModelSource>,
    supplied: Rc<ModelSource>,
    maximum: usize,
) -> OriginalConformanceEnrollmentFailure {
    let (profile, nodes, resources, plan) = local(&source);
    let selection = ProviderPlanningRequest {
        profile: &profile,
        configuration: &source.binding.configuration_ref,
        nodes: &nodes,
        resources: &resources,
        limits: ProviderRegistryLimits::default(),
    };
    match source.runner().finish_for_installation(
        supplied,
        selection,
        &plan,
        AcceptanceLimits {
            maximum_record_bytes: maximum,
            ..AcceptanceLimits::default()
        },
    ) {
        Ok(_) => panic!("unqualified model must not install ordinary acceptance"),
        Err(failure) => failure,
    }
}

#[test]
fn missing_original_population_never_installs_a_class_revision_and_retains_complete_audit() {
    let source = Rc::new(ModelSource::new(false));
    let failure = enroll(
        source.clone(),
        source.clone(),
        AcceptanceLimits::default().maximum_record_bytes,
    );
    let original = failure.original.originals().unwrap();
    assert!(original.attempts.attempted_cases().is_empty());
    let issued = original.issued.as_ref().unwrap();
    assert_eq!(issued.bytes(), source.claim_bytes);
    let claim: QualificationClaim = serde_json::from_slice(issued.bytes()).unwrap();
    assert!(
        claim
            .requirements
            .iter()
            .all(|row| row.disposition == RequirementDisposition::NotExecuted)
    );
    assert!(matches!(
        failure.original.record().unwrap().unwrap().decision,
        AcceptanceDecision::Refused { .. }
    ));
}

#[test]
fn foreign_same_data_source_refuses_before_callbacks_and_keeps_original_population() {
    let source = Rc::new(ModelSource::new(false));
    let foreign = Rc::new(ModelSource::new(false));
    assert_eq!(source.claim_bytes, foreign.claim_bytes);
    source.calls.set(0);
    foreign.calls.set(0);
    let failure = enroll(
        source.clone(),
        foreign.clone(),
        AcceptanceLimits::default().maximum_record_bytes,
    );
    // runner creation checks the original source once; enrollment cannot call foreign.
    assert_eq!(source.calls.get(), 1);
    assert_eq!(foreign.calls.get(), 0);
    assert_eq!(
        failure
            .original
            .originals()
            .unwrap()
            .issued
            .as_ref()
            .unwrap()
            .bytes(),
        source.claim_bytes
    );
    assert!(failure.original.record().unwrap().is_none());
}

#[test]
fn exhausted_enrollment_credit_keeps_original_before_source_callbacks_or_binding_copies() {
    let source = Rc::new(ModelSource::new(false));
    let failure = enroll(source.clone(), source.clone(), 1);
    assert_eq!(source.calls.get(), 1);
    assert!(failure.original.record().unwrap().is_none());
    assert_eq!(
        failure
            .original
            .originals()
            .unwrap()
            .issued
            .as_ref()
            .unwrap()
            .bytes(),
        source.claim_bytes
    );
}

#[test]
fn source_plan_callback_unwind_returns_the_same_unmodified_original_population() {
    let source = Rc::new(ModelSource::new(true));
    let failure = enroll(
        source.clone(),
        source.clone(),
        AcceptanceLimits::default().maximum_record_bytes,
    );
    assert!(matches!(
        failure.error,
        QualificationError::Refused("original enrollment source callback panicked")
    ));
    assert!(failure.original.record().unwrap().is_none());
    assert_eq!(
        failure
            .original
            .originals()
            .unwrap()
            .issued
            .as_ref()
            .unwrap()
            .bytes(),
        source.claim_bytes
    );
}

#[test]
fn foreign_creator_retains_unissued_population_without_encoding_or_source_callbacks() {
    let source = Rc::new(ModelSource::new(false));
    let (profile, nodes, resources, plan) = local(&source);
    let selection = ProviderPlanningRequest {
        profile: &profile,
        configuration: &source.binding.configuration_ref,
        nodes: &nodes,
        resources: &resources,
        limits: ProviderRegistryLimits::default(),
    };
    let mut runner = source.runner();
    runner.process = u32::MAX;
    let failure = match runner.finish_for_installation(
        source.clone(),
        selection,
        &plan,
        AcceptanceLimits::default(),
    ) {
        Ok(_) => panic!("modeled foreign creator cannot enroll"),
        Err(failure) => failure,
    };
    assert_eq!(source.calls.get(), 1);
    assert!(failure.original.unissued.is_some());
    assert!(failure.original.originals.issued.is_err());
    assert!(failure.original.record.is_none());
    assert!(failure.original.originals().is_err());
}

#[test]
fn final_source_plan_requery_observes_withdrawal_before_returning_original_scope() {
    let source = Rc::new(ModelSource::new(false));
    let failure = enroll(
        source.clone(),
        source.clone(),
        AcceptanceLimits::default().maximum_record_bytes,
    );
    let (profile, nodes, resources, plan) = local(&source);
    let local = OriginalProviderPlan {
        profile,
        configuration: source.binding.configuration_ref.clone(),
        nodes,
        resources,
        plan,
        limits: ProviderRegistryLimits::default(),
    };
    failure.original.final_scope_after_evidence(&local).unwrap();
    let before = source.calls.get();
    source.withdraw_on_plan.set(true);
    assert!(failure.original.final_scope_after_evidence(&local).is_err());
    assert_eq!(source.calls.get(), before + 2);
    assert!(source.withdrawn.get());
    assert_eq!(
        failure
            .original
            .originals()
            .unwrap()
            .issued
            .as_ref()
            .unwrap()
            .bytes(),
        source.claim_bytes
    );
}

#[test]
fn terminal_revision_fence_refuses_callback_revocation_with_unchanged_source_scope() {
    let source = Rc::new(ModelSource::new(false));
    let failure = enroll(
        source.clone(),
        source.clone(),
        AcceptanceLimits::default().maximum_record_bytes,
    );
    let (profile, nodes, resources, plan) = local(&source);
    let local = OriginalProviderPlan {
        profile,
        configuration: source.binding.configuration_ref.clone(),
        nodes,
        resources,
        plan,
        limits: ProviderRegistryLimits::default(),
    };
    let scope = ProviderAuthorizationScope::from_plan(
        ProviderPlanningRequest {
            profile: &local.profile,
            configuration: &local.configuration,
            nodes: &local.nodes,
            resources: &local.resources,
            limits: local.limits,
        },
        &local.plan,
    )
    .unwrap();
    // This model-only fence is deliberately independent of Accepted coverage.
    let revision = Rc::new(InstalledProviderRevision::new(
        scope.clone(),
        ProviderAuthorityKind::CatalogClass,
    ));
    failure
        .original
        .terminal_scope(&local, &source.binding, &revision, &scope)
        .unwrap();
    *source.revision_to_revoke.borrow_mut() = Some(revision.clone());
    assert!(
        failure
            .original
            .terminal_scope(&local, &source.binding, &revision, &scope)
            .is_err()
    );
    assert!(!source.withdrawn.get());
    failure.original.current_scope().unwrap();
    assert!(
        revision
            .lease()
            .authenticate(&scope, ProviderAuthorityKind::CatalogClass)
            .is_err()
    );
    assert_eq!(
        failure
            .original
            .originals()
            .unwrap()
            .issued
            .as_ref()
            .unwrap()
            .bytes(),
        source.claim_bytes
    );
}

#[test]
fn new_report_qualifies_only_a_distinct_future_binding_and_preserves_original_source_roster() {
    let mut source = ModelSource::new(false);
    let predecessor =
        canonical::content_ref(b"original source collecting mechanism", "text/plain").unwrap();
    source.binding.qualification_refs = vec![predecessor.clone()];
    let original_bytes = serde_json::to_vec(&source.binding).unwrap();
    assert!(
        !source
            .binding
            .qualification_refs
            .contains(&source.claim_reference)
    );
    let source = Rc::new(source);
    let (profile, nodes, resources, mut plan) = local(&source);
    plan.bindings[0]
        .qualification_refs
        .push(source.claim_reference.clone());
    plan.bindings[0]
        .qualification_refs
        .sort_by(|a, b| (&a.hash.domain, &a.hash.digest).cmp(&(&b.hash.domain, &b.hash.digest)));
    authenticate_future_binding(&source.binding, &plan.bindings[0], &source.claim_reference)
        .unwrap();
    let selection = ProviderPlanningRequest {
        profile: &profile,
        configuration: &source.binding.configuration_ref,
        nodes: &nodes,
        resources: &resources,
        limits: ProviderRegistryLimits::default(),
    };
    let failure = match source.runner().finish_for_installation(
        source.clone(),
        selection,
        &plan,
        AcceptanceLimits::default(),
    ) {
        Ok(_) => panic!("missing native model cases must still refuse full acceptance"),
        Err(failure) => failure,
    };
    // The new report reached the genuine full gate without requiring a prior
    // binding to predict its dynamic content reference. Missing coverage stays Refused.
    assert!(matches!(
        failure.original.record().unwrap().unwrap().decision,
        AcceptanceDecision::Refused { .. }
    ));
    assert_eq!(serde_json::to_vec(&source.binding).unwrap(), original_bytes);
    assert_ne!(
        source.binding.identity().unwrap(),
        plan.bindings[0].identity().unwrap()
    );
    let mut dropped = plan.bindings[0].clone();
    dropped
        .qualification_refs
        .retain(|reference| reference != &predecessor);
    assert!(
        authenticate_future_binding(&source.binding, &dropped, &source.claim_reference).is_err()
    );
    let mut extra = plan.bindings[0].clone();
    extra
        .qualification_refs
        .push(canonical::content_ref(b"unrelated extra claim", "text/plain").unwrap());
    extra
        .qualification_refs
        .sort_by(|a, b| (&a.hash.domain, &a.hash.digest).cmp(&(&b.hash.domain, &b.hash.digest)));
    assert!(authenticate_future_binding(&source.binding, &extra, &source.claim_reference).is_err());
    let mut changed = plan.bindings[0].clone();
    changed.configuration_ref.media_type.push_str("/foreign");
    assert!(
        authenticate_future_binding(&source.binding, &changed, &source.claim_reference).is_err()
    );
}

#[test]
fn original_scope_retains_issued_report_without_requiring_it_in_prebirth_binding() {
    let mut original_source = ModelSource::new(false);
    original_source.binding.qualification_refs.clear();
    let source = Rc::new(original_source);
    let binding_before = source.binding.clone();
    let failure = enroll(
        source.clone(),
        source.clone(),
        AcceptanceLimits::default().maximum_record_bytes,
    );

    let scope = failure.original.current_scope().unwrap();
    assert_eq!(scope.binding, &binding_before);
    assert_eq!(scope.original_claim, &source.claim_reference);
    assert_eq!(scope.original_bytes, source.claim_bytes);
    assert!(
        !scope
            .binding
            .qualification_refs
            .contains(scope.original_claim)
    );
    assert_eq!(source.binding, binding_before);
    // The local plan above deliberately lacks the new report; source provenance
    // can be read, but only the exact future union may reach full acceptance.
    assert!(failure.original.record().unwrap().is_none());
}

#[test]
fn source_inspection_attempt_retains_original_output_after_authentication_refusal_and_no_retry() {
    let mut source = ModelSource::new(false);
    source.plan.cases[0].kind = CaseKind::SourceInspection;
    source.plan_bytes =
        canonical::canonical_json(&serde_json::to_value(&source.plan).unwrap()).unwrap();
    source.plan_reference = canonical::content_ref(&source.plan_bytes, "application/json").unwrap();
    let mut runner = source.runner();
    assert!(runner.run_source_inspection("model/missing", 4096).is_err());
    let original = runner.source_inspections().get("model/missing").unwrap();
    assert_eq!(
        original.bytes(),
        br#"{"model":"unqualified source original"}"#
    );
    assert_eq!(
        original.outcome(),
        super::super::SourceInspectionOutcome::Returned
    );
    let calls = source.calls.get();
    assert!(runner.run_source_inspection("model/missing", 4096).is_err());
    assert_eq!(source.calls.get(), calls);
    let collected = runner.finish();
    assert!(collected.issued.is_err());
    assert_eq!(collected.source_inspections.len(), 1);
}

#[test]
fn source_inspection_refusal_and_unwind_keep_written_original_without_native_promotion() {
    for action in [1, 2] {
        let mut source = ModelSource::new(false);
        source.plan.cases[0].kind = CaseKind::SourceInspection;
        source.plan_bytes =
            canonical::canonical_json(&serde_json::to_value(&source.plan).unwrap()).unwrap();
        source.plan_reference =
            canonical::content_ref(&source.plan_bytes, "application/json").unwrap();
        source.source_inspection_action.set(action);
        let mut runner = source.runner();
        assert!(runner.run_source_inspection("model/missing", 4096).is_err());
        let original = runner.source_inspections().get("model/missing").unwrap();
        assert_eq!(
            original.bytes(),
            br#"{"model":"unqualified source original"}"#
        );
        assert_eq!(
            original.outcome(),
            if action == 1 {
                super::super::SourceInspectionOutcome::Refused
            } else {
                super::super::SourceInspectionOutcome::Unwound
            }
        );
        assert!(runner.finish().issued.is_err());
    }
}

#[test]
fn source_inspection_rejects_wrong_case_kind_and_credit_before_installed_execution() {
    let source = ModelSource::new(false);
    let mut runner = source.runner();
    let before = source.calls.get();
    assert!(runner.run_source_inspection("model/missing", 4096).is_err());
    assert!(runner.run_source_inspection("absent", 4096).is_err());
    assert!(runner.run_source_inspection("model/missing", 0).is_err());
    assert_eq!(source.calls.get(), before);
    assert!(runner.source_inspections().is_empty());
    assert!(runner.finish().attempts.attempted_cases().is_empty());
}
