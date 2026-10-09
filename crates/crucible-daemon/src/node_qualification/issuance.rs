//! Preserves a predeclared witness population while assembling original claims.
//!
//! A source-installed authority authenticates the complete plan before case
//! observations can be recorded. Issuance retains failed and unexecuted cases;
//! it grants neither ledger acceptance nor native readiness. An independent
//! installation authority still verifies the original observations and oracles
//! through the admission and release gates.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use crucible_node_contract::{Bytes, ContentRef, Validate, canonical};
use serde::{Deserialize, Serialize};

use super::{
    CaseEvidence, CaseKind, CaseVerdict, QualificationClaim, QualificationClass,
    QualificationError, QualificationLimits, QualificationUnit, RequirementDisposition,
    RequirementResult, normative_specification, requirement_catalog,
};

/// Binds one original case before its native or inspection witness executes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedWitnessCase {
    /// Names the immutable original case, including its predeclared retry scope.
    pub id: String,
    /// Identifies the actual observation mechanism without upgrading models.
    pub kind: CaseKind,
    /// Enumerates the exact classes this independent case can cover.
    pub classes: BTreeSet<QualificationClass>,
    /// Binds the independent expected property and its fixture/source identity.
    pub oracle: ContentRef,
}

/// States source-owned coverage or precise nonapplicability for an obligation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "snake_case", deny_unknown_fields)]
pub enum WitnessCriterion {
    /// Requires every named original case and the exact declared class scope.
    Applicable {
        /// Lists original case IDs in strictly increasing order.
        cases: Vec<String>,
        /// Binds the explicit inspection/oracle criterion, not a passing label.
        criterion: ContentRef,
    },
    /// Excludes the obligation under an authenticated installed restriction.
    NotApplicable {
        /// Gives the exact source-owned policy rationale.
        reason: String,
        /// Binds the source inspection establishing this scope restriction.
        criterion: ContentRef,
    },
}

/// Describes the entire source-installed population before native effects.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessPlan {
    /// Names the closed plan format, `crucible.node-witness-plan.v1`.
    pub schema: String,
    /// Binds independently measured source, realization and environment axes.
    pub unit: QualificationUnit,
    /// Enumerates exactly the advertised classes, without inferred guarantees.
    pub classes: BTreeSet<QualificationClass>,
    /// Maps every compiled RFC obligation to one explicit installed criterion.
    pub requirements: BTreeMap<String, WitnessCriterion>,
    /// Lists every original case once, including adverse and inspection cases.
    pub cases: Vec<PlannedWitnessCase>,
    /// Binds known difficult-state exclusions and expiry conditions.
    pub limitations: ContentRef,
}

/// Authenticates source-owned witness issuance independently of providers.
///
/// A hash or caller-selected signing key cannot establish this authority. The
/// installer must authenticate the actual harness/package, exact plan and
/// original observation mechanism, including complete failed-case populations.
pub trait InstalledWitnessAuthority {
    /// Authenticates the original complete plan before observations are accepted.
    ///
    /// # Errors
    /// Refuses unknown issuers, changed harness/fixture/source scope or policy,
    /// incomplete criteria, unsupported classes or unverified exclusions.
    fn authenticate_plan(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        plan: &WitnessPlan,
    ) -> Result<(), QualificationError>;

    /// Authenticates one original result and its actual independent oracle.
    ///
    /// Authentication preserves the supplied verdict, including failures. It
    /// must not silently choose a passing retry or promote protocol-only data
    /// into native evidence. Unknown effects are retained as failed evidence.
    ///
    /// # Errors
    /// Refuses unavailable original observations, changed case identity/scope,
    /// altered classifications, incomplete custody or rewritten oracle facts.
    fn authenticate_result(
        &self,
        plan: &WitnessPlan,
        case: &PlannedWitnessCase,
        verdict: CaseVerdict,
        result: &ContentRef,
        bytes: &[u8],
    ) -> Result<(), QualificationError>;
}

/// Accumulates original observations without replacing a failed attempt.
pub struct WitnessPopulation {
    plan: WitnessPlan,
    plan_reference: ContentRef,
    plan_bytes: Vec<u8>,
    recorded: BTreeMap<String, (CaseEvidence, Bytes)>,
    limits: QualificationLimits,
    recorded_bytes: u64,
}

/// Retains issued original bytes and available evidence without conferring trust.
pub struct IssuedQualification {
    claim: ContentRef,
    bytes: Vec<u8>,
    objects: Vec<(ContentRef, Bytes)>,
}

impl IssuedQualification {
    /// Returns the immutable original claim identity.
    pub fn reference(&self) -> &ContentRef {
        &self.claim
    }

    /// Returns the original canonical report bytes, including failed rows.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the plan and original results that must remain available.
    pub fn objects(&self) -> &[(ContentRef, Bytes)] {
        &self.objects
    }
}

impl WitnessPopulation {
    /// Installs a complete independently authenticated plan before collection.
    ///
    /// # Errors
    /// Refuses noncanonical, oversized or changed bytes; incomplete normative
    /// coverage; unreferenced or duplicate cases; and untrusted installed policy.
    pub fn install(
        bytes: &[u8],
        reference: &ContentRef,
        authority: &dyn InstalledWitnessAuthority,
        limits: QualificationLimits,
    ) -> Result<Self, QualificationError> {
        if bytes.len() > limits.maximum_claim_bytes
            || reference.length.get() > limits.maximum_evidence_bytes
            || reference.length.get() > limits.maximum_total_evidence_bytes
        {
            return Err(QualificationError::Refused("witness plan byte ceiling"));
        }
        reference.verify(bytes)?;
        let value = canonical::parse_json(bytes, limits.maximum_claim_bytes)?;
        if canonical::canonical_json(&value)? != bytes {
            return Err(QualificationError::Refused("noncanonical witness plan"));
        }
        let plan: WitnessPlan =
            serde_json::from_value(value).map_err(crucible_node_contract::ContractError::from)?;
        validate_plan(&plan, limits)?;
        authority.authenticate_plan(reference, bytes, &plan)?;

        Ok(Self {
            plan,
            plan_reference: reference.clone(),
            plan_bytes: copy_bytes(bytes)?,
            recorded: BTreeMap::new(),
            limits,
            recorded_bytes: 0,
        })
    }

    /// Retains one authenticated original verdict and its unchanged result bytes.
    ///
    /// # Errors
    /// Refuses replacement/retry under an already recorded ID, an unknown case,
    /// unavailable original evidence, integrity failures or exhausted credits.
    pub fn record(
        &mut self,
        case_id: &str,
        verdict: CaseVerdict,
        reference: &ContentRef,
        bytes: &[u8],
        authority: &dyn InstalledWitnessAuthority,
    ) -> Result<(), QualificationError> {
        if self.recorded.contains_key(case_id) {
            return Err(QualificationError::Refused(
                "original witness already retained",
            ));
        }
        let case = self
            .plan
            .cases
            .iter()
            .find(|case| case.id == case_id)
            .ok_or(QualificationError::Refused("unplanned witness case"))?;
        let total = self
            .recorded_bytes
            .checked_add(reference.length.get())
            .ok_or(QualificationError::Refused(
                "witness evidence byte overflow",
            ))?;
        if reference.length.get() > self.limits.maximum_evidence_bytes
            || total
                .checked_add(self.plan_reference.length.get())
                .is_none_or(|all| all > self.limits.maximum_total_evidence_bytes)
        {
            return Err(QualificationError::Refused("witness evidence byte ceiling"));
        }
        reference.verify(bytes)?;
        authority.authenticate_result(&self.plan, case, verdict, reference, bytes)?;
        let evidence = CaseEvidence {
            case: case.id.clone(),
            kind: case.kind,
            verdict,
            classes: case.classes.clone(),
            result: reference.clone(),
            oracle: case.oracle.clone(),
        };
        self.recorded
            .insert(case.id.clone(), (evidence, Bytes::new(copy_bytes(bytes)?)));
        self.recorded_bytes = total;
        Ok(())
    }

    /// Issues the complete population, retaining every unexecuted case explicitly.
    ///
    /// Missing observations produce `NotExecuted`, never synthetic success.
    /// The result remains data; [`super::accept_claim`] independently verifies
    /// every applicable row and rejects any unresolved population.
    ///
    /// # Errors
    /// Refuses invalid content, serialization, exhausted report/evidence credits
    /// or missing internally declared case references.
    pub fn finish(mut self) -> Result<IssuedQualification, QualificationError> {
        let object_count =
            self.plan
                .cases
                .len()
                .checked_add(1)
                .ok_or(QualificationError::Refused(
                    "issued witness object overflow",
                ))?;
        if object_count > self.limits.maximum_evidence_objects {
            return Err(QualificationError::Refused("issued witness object ceiling"));
        }
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(object_count)
            .map_err(|_| QualificationError::Refused("issued witness object allocation"))?;
        objects.push((self.plan_reference.clone(), Bytes::new(self.plan_bytes)));
        for case in &self.plan.cases {
            if !self.recorded.contains_key(&case.id) {
                let value = serde_json::json!({
                    "schema": "crucible.unexecuted-witness.v1",
                    "plan": self.plan_reference,
                    "case": case.id,
                    "verdict": "not_executed",
                });
                let bytes = canonical::canonical_json(&value)?;
                let result = canonical::content_ref(&bytes, "application/json")?;
                let total = self
                    .recorded_bytes
                    .checked_add(result.length.get())
                    .ok_or(QualificationError::Refused("issued witness byte overflow"))?;
                if result.length.get() > self.limits.maximum_evidence_bytes
                    || total
                        .checked_add(self.plan_reference.length.get())
                        .is_none_or(|all| all > self.limits.maximum_total_evidence_bytes)
                {
                    return Err(QualificationError::Refused("issued witness byte ceiling"));
                }
                self.recorded.insert(
                    case.id.clone(),
                    (
                        CaseEvidence {
                            case: case.id.clone(),
                            kind: case.kind,
                            verdict: CaseVerdict::NotExecuted,
                            classes: case.classes.clone(),
                            result,
                            oracle: case.oracle.clone(),
                        },
                        Bytes::new(bytes),
                    ),
                );
                self.recorded_bytes = total;
            }
        }
        let mut requirements = Vec::new();
        requirements
            .try_reserve_exact(self.plan.requirements.len())
            .map_err(|_| QualificationError::Refused("issued requirement allocation"))?;
        for (requirement, criterion) in &self.plan.requirements {
            let (disposition, cases, not_applicable_reason) = match criterion {
                WitnessCriterion::NotApplicable { reason, .. } => (
                    RequirementDisposition::NotApplicable,
                    Vec::new(),
                    Some(reason.clone()),
                ),
                WitnessCriterion::Applicable { cases, .. } => {
                    let cases = cases
                        .iter()
                        .map(|id| {
                            self.recorded
                                .get(id)
                                .map(|(case, _)| case.clone())
                                .ok_or(QualificationError::Refused("declared case unavailable"))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let disposition = population_disposition(&cases);
                    (disposition, cases, None)
                }
            };
            requirements.push(RequirementResult {
                requirement: requirement.clone(),
                disposition,
                cases,
                not_applicable_reason,
            });
        }
        objects.extend(
            self.recorded
                .into_values()
                .map(|(case, bytes)| (case.result, bytes)),
        );
        let claim = QualificationClaim {
            format: "crucible.node-qualification".into(),
            version: 1,
            unit: self.plan.unit,
            classes: self.plan.classes,
            catalog: requirement_catalog()?.0,
            applicability_policy: self.plan_reference,
            requirements,
            supersedes: None,
            limitations: self.plan.limitations,
        };
        // Check the serialized ceiling before constructing a second owned JSON
        // tree; repeated case references cannot expand a small plan unboundedly.
        serde_json::to_writer(&mut EncodingBudget(self.limits.maximum_claim_bytes), &claim)
            .map_err(|_| QualificationError::Refused("issued witness report byte ceiling"))?;
        let bytes = canonical::canonical_json(
            &serde_json::to_value(&claim).map_err(crucible_node_contract::ContractError::from)?,
        )?;
        if bytes.len() > self.limits.maximum_claim_bytes {
            return Err(QualificationError::Refused(
                "issued witness report byte ceiling",
            ));
        }
        let reference = canonical::content_ref(&bytes, "application/json")?;
        Ok(IssuedQualification {
            claim: reference,
            bytes,
            objects,
        })
    }
}

fn validate_plan(
    plan: &WitnessPlan,
    limits: QualificationLimits,
) -> Result<(), QualificationError> {
    plan.unit.validate()?;
    plan.limitations.validate()?;
    if plan.schema != "crucible.node-witness-plan.v1"
        || plan.unit.specification != normative_specification()?.0
        || plan.classes.is_empty()
        || !plan.classes.contains(&QualificationClass::BaseProvider)
        || plan.cases.is_empty()
        || plan.cases.len() > limits.maximum_cases
    {
        return Err(QualificationError::Refused(
            "invalid source witness plan scope",
        ));
    }
    let catalog = requirement_catalog()?.1;
    if plan.requirements.len() != catalog.len()
        || !plan.requirements.keys().map(String::as_str).eq(catalog)
    {
        return Err(QualificationError::Refused(
            "incomplete witness requirement plan",
        ));
    }
    let mut cases = BTreeMap::new();
    for case in &plan.cases {
        case.oracle.validate()?;
        if case.id.is_empty()
            || case.id.len() > 256
            || case.classes.is_empty()
            || !case.classes.is_subset(&plan.classes)
            || cases.insert(&case.id, case).is_some()
        {
            return Err(QualificationError::Refused(
                "invalid predeclared witness case",
            ));
        }
    }
    let mut used = BTreeSet::new();
    let mut coverage_entries = 0usize;
    for criterion in plan.requirements.values() {
        match criterion {
            WitnessCriterion::NotApplicable { reason, criterion } => {
                criterion.validate()?;
                if reason.is_empty() || reason.len() > 4096 {
                    return Err(QualificationError::Refused(
                        "invalid installed witness exclusion",
                    ));
                }
            }
            WitnessCriterion::Applicable {
                cases: selected,
                criterion,
            } => {
                criterion.validate()?;
                coverage_entries = coverage_entries
                    .checked_add(selected.len())
                    .ok_or(QualificationError::Refused("witness coverage overflow"))?;
                if selected.is_empty()
                    || selected.len() > cases.len()
                    || coverage_entries > limits.maximum_cases
                    || selected.windows(2).any(|pair| pair[0] >= pair[1])
                {
                    return Err(QualificationError::Refused(
                        "invalid witness criterion population",
                    ));
                }
                for id in selected {
                    if !cases.contains_key(id) {
                        return Err(QualificationError::Refused("unknown criterion case"));
                    }
                    used.insert(id);
                }
            }
        }
    }
    if used.len() != cases.len() {
        return Err(QualificationError::Refused(
            "unreferenced original witness case",
        ));
    }
    Ok(())
}

fn population_disposition(cases: &[CaseEvidence]) -> RequirementDisposition {
    if cases.iter().any(|case| case.verdict == CaseVerdict::Failed) {
        RequirementDisposition::Failed
    } else if cases
        .iter()
        .any(|case| case.verdict == CaseVerdict::NotExecuted)
    {
        RequirementDisposition::NotExecuted
    } else if cases
        .iter()
        .any(|case| case.verdict == CaseVerdict::Unsupported)
    {
        RequirementDisposition::Unsupported
    } else {
        RequirementDisposition::Passed
    }
}

fn copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, QualificationError> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| QualificationError::Refused("original witness byte allocation"))?;
    owned.extend_from_slice(bytes);
    Ok(owned)
}

struct EncodingBudget(usize);

impl Write for EncodingBudget {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("witness report byte ceiling"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
