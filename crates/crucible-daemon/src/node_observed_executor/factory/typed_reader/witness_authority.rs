//! Joins independent typed-source installation to original host report custody.
//!
//! One shared host object authenticates the complete fixed programme and current
//! Refused scopes, enrolls native source windows before reports, and retains the
//! runner's original reports. Ordinary claim and case acceptance always refuse.

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};

use crucible::node_adapters::cnp::OriginalRuntimeLineage;
use crucible::node_contract::{InputProvenanceClosure, OperationOutcome, OriginalInputLineage};
use crucible::node_scheduling::RuntimeInputBatch;
use crucible_node_contract::{ContentRef, Id, ResourceLimits, canonical};
use crucible_node_provider::{
    ProviderError,
    client::OriginalLineageRealization,
    reference_lineage::LineageSourceGuard,
    reference_service::{ReferenceNegotiatedLineageReaderLaunchBootstrap, ReferenceProfile},
};
use serde::Serialize;

use super::{
    InstalledTypedReaderFixtureAuthority, InstalledTypedReaderPackage,
    InstalledTypedReaderSourceFixture, TypedReaderFixtureAudit, TypedReaderNativeOracles,
    TypedReaderProgramme,
};
use crate::node_qualification::{
    AcceptanceDecision, AcceptanceScope, Applicability, CaseEvidence, CaseVerdict,
    InstalledAcceptancePolicy, InstalledConformanceAuthority, InstalledQualificationAuthority,
    InstalledRuntimeWitnessOracle, InstalledWitnessAuthority, OriginalCompletionWitness,
    OriginalRuntimeReportStore, PlannedWitnessCase, QualificationClaim, QualificationClass,
    QualificationError, QualificationLimits, QualificationUnit, QuantizedCompletionCase,
    WitnessPlan,
};

mod collection;

struct ScopeSeal {
    node: Id,
    reference: ContentRef,
}

#[path = "witness_authority/final_current.rs"]
mod final_current;

/// Owns the shared finite typed fixture's native oracles and original reports.
///
/// Independent source installation remains mandatory. The inner installed
/// source fixture must authenticate private launch/kernel/namespace authority,
/// original realization and complete input/staging oracles. This wrapper adds
/// host custody and exact plan joins; it cannot install trust from package data.
pub struct TypedReaderWitnessAuthority {
    collection: collection::CollectionPolicy,
    source: Rc<InstalledTypedReaderSourceFixture>,
    audit: Rc<TypedReaderFixtureAudit>,
    programme: Rc<TypedReaderProgramme>,
    plan: WitnessPlan,
    plan_reference: ContentRef,
    scopes: Vec<ScopeSeal>,
    oracles: TypedReaderNativeOracles,
    reports: RefCell<OriginalRuntimeReportStore>,
    limits: QualificationLimits,
}

impl TypedReaderWitnessAuthority {
    /// Reserves complete programme, original report slots and Refused scope seals.
    ///
    /// The source and programme are borrowed during validation, so refusal
    /// leaves both original owners with the caller. No files, sockets or Child
    /// work occurs. Every source scope is independently reopened before sealing.
    ///
    /// # Errors
    /// Refuses unavailable independent installation, altered complete plan,
    /// accepted or substituted scopes, insufficient pre-copy credit or capacity.
    pub fn new(
        source: &Rc<InstalledTypedReaderSourceFixture>,
        audit: &Rc<TypedReaderFixtureAudit>,
        programme: &Rc<TypedReaderProgramme>,
        plan: &WitnessPlan,
        reference: &ContentRef,
        limits: QualificationLimits,
        maximum_report_bytes: usize,
    ) -> Result<Self, QualificationError> {
        super::programme::count(&(plan, reference), limits.maximum_claim_bytes)
            .map_err(provider_error)?;
        let expected = programme
            .witness_plan(plan.unit.clone(), plan.limitations.clone())
            .map_err(provider_error)?;
        if expected != *plan {
            return Err(refused());
        }
        let bytes = encoded(plan, limits.maximum_claim_bytes)?;
        reference.verify(&bytes)?;
        source.authenticate_plan(reference, &bytes, plan)?;
        if audit.record().evaluated_unit != plan.unit
            || audit.record().required_classes != plan.classes
            || audit.record().original.applicability_policy != *reference
            || !matches!(audit.record().decision, AcceptanceDecision::Refused { .. })
        {
            return Err(refused());
        }
        audit.claim().verify(audit.original_bytes())?;

        let mut scopes = Vec::new();
        scopes
            .try_reserve_exact(programme.peers.len())
            .map_err(|_| refused())?;
        for peer in &programme.peers {
            let scope = source_scope(source, audit, plan, &peer.node, limits.maximum_claim_bytes)?;
            scopes.push(ScopeSeal {
                node: peer.node.clone(),
                reference: scope_reference(&scope, limits.maximum_claim_bytes)?,
            });
        }
        let reports = OriginalRuntimeReportStore::new(
            &PlanAuthentication(source.as_ref()),
            plan,
            reference,
            limits,
            maximum_report_bytes,
        )?;
        let oracles =
            TypedReaderNativeOracles::new(Rc::clone(programme)).map_err(provider_error)?;
        Ok(Self {
            collection: collection::CollectionPolicy::new(),
            source: Rc::clone(source),
            audit: Rc::clone(audit),
            programme: Rc::clone(programme),
            plan: plan.clone(),
            plan_reference: reference.clone(),
            scopes,
            oracles,
            reports: RefCell::new(reports),
            limits,
        })
    }

    /// Borrows the exact independently frozen finite programme.
    pub fn programme(&self) -> &TypedReaderProgramme {
        &self.programme
    }

    /// Derives the complete outcome from an independently enrolled source window.
    ///
    /// The native oracle remains private. A source window can be enrolled only
    /// after this object's independent installation and kernel checks succeed.
    ///
    /// # Errors
    /// Refuses a changed plan or a case without its original native source seal.
    pub fn expected_outcome(&self, case: &str) -> Result<OperationOutcome, ProviderError> {
        self.current_plan(&self.plan_reference)?;
        self.oracles.expected_outcome(case)
    }

    /// Builds a finite collector case from independently enrolled source originals.
    ///
    /// Fixed permission and semantic expectations come from the prelaunch
    /// programme. Unpredictable native outcome, input and Stage identities come
    /// from source callbacks retained before common report inspection.
    ///
    /// # Errors
    /// Refuses an unknown case, changed current installation, unavailable native
    /// or Stage originals, zero budget or insufficient pre-copy body credit.
    pub fn quantized_case(
        &self,
        case: &str,
        maximum_bytes: u64,
    ) -> Result<QuantizedCompletionCase, ProviderError> {
        self.current_plan(&self.plan_reference)?;
        let maximum = usize::try_from(maximum_bytes).map_err(|_| unavailable())?;
        if maximum == 0 {
            return Err(unavailable());
        }
        let planned = self
            .programme
            .windows()
            .iter()
            .find(|planned| planned.case == case)
            .ok_or_else(unavailable)?;
        let outcome = self.oracles.expected_outcome(case)?;
        let (input, staging) = self.source.completion_input_oracles(case)?;
        super::programme::count(
            &(
                case,
                self.programme.reference(),
                &planned.request,
                &outcome,
                &input,
                &staging,
                true,
                maximum_bytes,
            ),
            maximum,
        )?;
        self.current_plan(&self.plan_reference)?;
        Ok(QuantizedCompletionCase {
            case: case.to_owned(),
            oracle: self.programme.reference().clone(),
            request: planned.request.clone(),
            outcome,
            input: Some(input),
            staging: Some(staging),
            acknowledged: true,
            maximum_bytes,
        })
    }

    pub(super) fn source(&self) -> &InstalledTypedReaderSourceFixture {
        &self.source
    }

    pub(super) fn current_plan(&self, plan: &ContentRef) -> Result<(), ProviderError> {
        self.source_plan(plan)
    }

    fn current(&self, plan: &WitnessPlan) -> Result<(), QualificationError> {
        if plan != &self.plan {
            return Err(refused());
        }
        let bytes = encoded(plan, self.limits.maximum_claim_bytes)?;
        self.plan_reference.verify(&bytes)?;
        self.source()
            .authenticate_plan(&self.plan_reference, &bytes, plan)?;
        for seal in &self.scopes {
            let scope = source_scope(
                &self.source,
                &self.audit,
                plan,
                &seal.node,
                self.limits.maximum_claim_bytes,
            )?;
            if scope_reference(&scope, self.limits.maximum_claim_bytes)? != seal.reference {
                return Err(refused());
            }
        }
        Ok(())
    }

    fn source_plan(&self, plan: &ContentRef) -> Result<(), ProviderError> {
        if plan != &self.plan_reference {
            return Err(source_refused());
        }
        self.current(&self.plan).map_err(|_| source_refused())
    }
}

impl InstalledQualificationAuthority for TypedReaderWitnessAuthority {
    fn authenticate_claim(
        &self,
        _: &ContentRef,
        _: &[u8],
        _: &QualificationClaim,
    ) -> Result<(), QualificationError> {
        Err(QualificationError::Refused(
            "typed collection has no accepted claim authority",
        ))
    }

    fn applicability(
        &self,
        unit: &QualificationUnit,
        classes: &BTreeSet<QualificationClass>,
        policy: &ContentRef,
    ) -> Result<BTreeMap<String, Applicability>, QualificationError> {
        self.current(&self.plan)?;
        if unit != &self.plan.unit
            || classes != &self.plan.classes
            || policy != &self.plan_reference
        {
            return Err(refused());
        }
        // The complete programme has no exclusions. Each placeholder remains a
        // required case, so nine actual windows cannot complete the population.
        super::programme::count(
            &ApplicabilityRows(&self.plan, classes),
            self.limits.maximum_claim_bytes,
        )
        .map_err(provider_error)?;
        let current = self
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
            .collect();
        Ok(current)
    }

    fn verify_evidence(
        &self,
        reference: &ContentRef,
        maximum_bytes: u64,
        maximum_dependencies: usize,
    ) -> Result<Vec<ContentRef>, QualificationError> {
        self.current(&self.plan)?;
        let _ = (reference, maximum_bytes, maximum_dependencies);
        Err(QualificationError::Refused(
            "typed fixture has no accepted evidence closure authority",
        ))
    }

    fn authenticate_case(
        &self,
        _: &QualificationUnit,
        _: &str,
        _: &CaseEvidence,
    ) -> Result<(), QualificationError> {
        Err(QualificationError::Refused(
            "typed collection has no ordinary case authority",
        ))
    }
}

impl InstalledAcceptancePolicy for TypedReaderWitnessAuthority {
    fn scope_for_node(&self, node: &Id) -> Result<AcceptanceScope<'_>, QualificationError> {
        self.current(&self.plan)?;
        if !self.scopes.iter().any(|seal| &seal.node == node) {
            return Err(refused());
        }
        source_scope(
            &self.source,
            &self.audit,
            &self.plan,
            node,
            self.limits.maximum_claim_bytes,
        )
    }
}

impl InstalledWitnessAuthority for TypedReaderWitnessAuthority {
    fn authenticate_plan(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        plan: &WitnessPlan,
    ) -> Result<(), QualificationError> {
        self.current(plan)?;
        if reference != &self.plan_reference
            || encoded(plan, self.limits.maximum_claim_bytes)? != bytes
        {
            return Err(refused());
        }
        reference.verify(bytes).map_err(QualificationError::from)
    }

    fn authenticate_result(
        &self,
        plan: &WitnessPlan,
        case: &PlannedWitnessCase,
        verdict: CaseVerdict,
        reference: &ContentRef,
        bytes: &[u8],
    ) -> Result<(), QualificationError> {
        self.current(plan)?;
        self.reports
            .try_borrow()
            .map_err(|_| refused())?
            .authenticate_result(plan, case, verdict, reference, bytes)
    }
}

impl InstalledRuntimeWitnessOracle for TypedReaderWitnessAuthority {
    fn authenticate_original(
        &self,
        plan: &WitnessPlan,
        case: &PlannedWitnessCase,
        original: &OriginalCompletionWitness<'_, '_>,
    ) -> Result<CaseVerdict, QualificationError> {
        self.current(plan)?;
        if !self.plan.cases.iter().any(|planned| planned == case)
            || case.oracle != *self.programme.reference()
        {
            return Err(refused());
        }
        self.oracles
            .authenticate_completion(&case.id, original)
            .map_err(provider_error)?;
        Ok(CaseVerdict::Passed)
    }
}

impl InstalledConformanceAuthority for TypedReaderWitnessAuthority {
    fn authenticate_quantized_fixture(
        &self,
        plan: &WitnessPlan,
        case: &QuantizedCompletionCase,
    ) -> Result<(), QualificationError> {
        self.current(plan)?;
        let planned = self
            .programme
            .windows()
            .iter()
            .find(|window| window.case == case.case)
            .ok_or_else(refused)?;
        if case.oracle != *self.programme.reference()
            || case.request != planned.request
            || case.outcome
                != self
                    .oracles
                    .expected_outcome(&case.case)
                    .map_err(provider_error)?
            || !case.acknowledged
            || case.maximum_bytes == 0
        {
            return Err(refused());
        }
        // These identities are enrolled from original source callbacks before
        // common completion inspection. Neither caller fields nor report bytes
        // can substitute for unavailable original Stage/native bodies.
        let (input, staging) = self
            .source
            .completion_input_oracles(&case.case)
            .map_err(provider_error)?;
        if case.input.as_ref() != Some(&input) || case.staging.as_ref() != Some(&staging) {
            return Err(refused());
        }
        self.current(plan)?;
        Ok(())
    }

    fn retain_original_runtime_witness(
        &self,
        plan: &WitnessPlan,
        case: &str,
        oracle: &ContentRef,
        original: &OriginalCompletionWitness<'_, '_>,
    ) -> Result<(), QualificationError> {
        self.current(plan)?;
        self.reports
            .try_borrow_mut()
            .map_err(|_| refused())?
            .observe(plan, case, oracle, original, self)
    }
}

impl InstalledTypedReaderFixtureAuthority for TypedReaderWitnessAuthority {
    fn authenticate_terminal_native(&self, plan: &ContentRef) -> Result<(), ProviderError> {
        self.current_plan(plan)?;
        self.source.authenticate_current_native_owners()
    }

    fn authenticate_fixture_plan(
        &self,
        package: &ContentRef,
        resources: &ResourceLimits,
    ) -> Result<ContentRef, ProviderError> {
        final_current::authenticate(
            || self.current_plan(&self.plan_reference),
            || {
                if package != self.programme.package() {
                    return Err(source_refused());
                }
                let original = self.source.authenticate_fixture_plan(package, resources)?;
                if original != self.plan_reference {
                    return Err(source_refused());
                }
                Ok(original)
            },
            Ok,
        )
    }

    fn authenticate_source(
        &self,
        plan: &ContentRef,
        package: &InstalledTypedReaderPackage,
        profile: &ReferenceProfile,
        resources: &ResourceLimits,
    ) -> Result<(), ProviderError> {
        final_current::authenticate(
            || self.source_plan(plan),
            || {
                self.source
                    .authenticate_source(plan, package, profile, resources)
            },
            Ok,
        )
    }

    fn authenticate_launch(
        &self,
        plan: &ContentRef,
        package: &InstalledTypedReaderPackage,
        profile: &ReferenceProfile,
        launch: &ReferenceNegotiatedLineageReaderLaunchBootstrap,
    ) -> Result<(), ProviderError> {
        final_current::authenticate(
            || self.source_plan(plan),
            || {
                self.source
                    .authenticate_launch(plan, package, profile, launch)
            },
            Ok,
        )
    }

    fn authenticate_realization(
        &self,
        plan: &ContentRef,
        package: &InstalledTypedReaderPackage,
        profile: &ReferenceProfile,
        guard: &LineageSourceGuard,
        original: &OriginalLineageRealization<'_>,
        resources: &ResourceLimits,
    ) -> Result<(), ProviderError> {
        final_current::authenticate(
            || self.source_plan(plan),
            || {
                self.source
                    .authenticate_realization(plan, package, profile, guard, original, resources)
            },
            Ok,
        )
    }

    fn authenticate_window(
        &self,
        plan: &ContentRef,
        package: &InstalledTypedReaderPackage,
        profile: &ReferenceProfile,
        original: &OriginalRuntimeLineage<'_>,
    ) -> Result<(), ProviderError> {
        final_current::authenticate(
            || self.source_plan(plan),
            || {
                self.source
                    .authenticate_window(plan, package, profile, original)
            },
            |()| self.oracles.enroll(original),
        )
    }

    fn authenticate_inputs(
        &self,
        plan: &ContentRef,
        package: &InstalledTypedReaderPackage,
        profile: &ReferenceProfile,
        original: &RuntimeInputBatch,
        provenance: &InputProvenanceClosure,
        lineage: &OriginalInputLineage,
    ) -> Result<(), ProviderError> {
        final_current::authenticate(
            || self.source_plan(plan),
            || {
                self.source
                    .authenticate_inputs(plan, package, profile, original, provenance, lineage)
            },
            |()| {
                self.oracles
                    .authenticate_inputs(original, provenance, lineage)
            },
        )
    }
}

fn source_scope<'a>(
    source: &'a InstalledTypedReaderSourceFixture,
    audit: &'a TypedReaderFixtureAudit,
    plan: &WitnessPlan,
    node: &Id,
    maximum_bytes: usize,
) -> Result<AcceptanceScope<'a>, QualificationError> {
    let binding = source.binding(node).map_err(provider_error)?;
    super::programme::count(binding, maximum_bytes).map_err(provider_error)?;
    let current_unit = source.current_unit(node).map_err(provider_error)?;
    if binding.node_id != *node
        || current_unit != plan.unit
        || !binding.qualification_refs.contains(audit.claim())
        || !binding
            .qualification_refs
            .contains(&audit.record().original.applicability_policy)
    {
        return Err(refused());
    }
    super::programme::count(
        &(binding, &current_unit, &audit.record().required_classes),
        maximum_bytes,
    )
    .map_err(provider_error)?;
    Ok(AcceptanceScope {
        binding,
        current_unit,
        required_classes: audit.record().required_classes.clone(),
        original_bytes: audit.original_bytes(),
        original_claim: audit.claim(),
        record: audit.record(),
    })
}

struct PlanAuthentication<'a>(&'a InstalledTypedReaderSourceFixture);

impl InstalledWitnessAuthority for PlanAuthentication<'_> {
    fn authenticate_plan(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        plan: &WitnessPlan,
    ) -> Result<(), QualificationError> {
        self.0.authenticate_plan(reference, bytes, plan)
    }

    fn authenticate_result(
        &self,
        _: &WitnessPlan,
        _: &PlannedWitnessCase,
        _: CaseVerdict,
        _: &ContentRef,
        _: &[u8],
    ) -> Result<(), QualificationError> {
        Err(refused())
    }
}

fn scope_reference(
    scope: &AcceptanceScope<'_>,
    maximum_bytes: usize,
) -> Result<ContentRef, QualificationError> {
    let bytes = encoded(
        &(
            scope.binding,
            &scope.current_unit,
            &scope.required_classes,
            scope.original_claim,
            scope.original_bytes,
            scope.record,
        ),
        maximum_bytes,
    )?;
    Ok(canonical::content_ref(&bytes, "application/json")?)
}

struct ApplicabilityRows<'a>(&'a WitnessPlan, &'a BTreeSet<QualificationClass>);

impl Serialize for ApplicabilityRows<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut rows = serializer.serialize_map(Some(self.0.requirements.len()))?;
        for id in self.0.requirements.keys() {
            rows.serialize_entry(id, self.1)?;
        }
        rows.end()
    }
}

fn encoded(value: &impl Serialize, maximum_bytes: usize) -> Result<Vec<u8>, QualificationError> {
    super::programme::count(value, maximum_bytes).map_err(provider_error)?;
    let value = serde_json::to_value(value).map_err(crucible_node_contract::ContractError::from)?;
    Ok(canonical::canonical_json(&value)?)
}

fn unavailable() -> ProviderError {
    ProviderError::Correlation("typed original completion source is unavailable")
}

fn provider_error(error: ProviderError) -> QualificationError {
    QualificationError::Evidence(error.to_string())
}

fn refused() -> QualificationError {
    QualificationError::Refused("original typed fixture installation or scope changed")
}

fn source_refused() -> ProviderError {
    ProviderError::Correlation("original typed host fixture authority unavailable")
}
