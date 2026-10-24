//! Enrolls genuine original observations through the complete qualification ledger.
//!
//! A source run is the only constructor of this report authority. No decoder,
//! provider Passed flag or hash list can install it. Every compiled obligation
//! stays present; partial lawful observations leave unsupported coverage pending.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use crate::node_qualification::{
    AcceptanceDecision, AcceptanceLimits, AcceptanceRecord, AcceptanceScope, Applicability,
    CaseEvidence, CaseKind, CaseVerdict, InstalledAcceptancePolicy,
    InstalledQualificationAuthority, QualificationClaim, QualificationClass, QualificationError,
    QualificationUnit, RequirementDisposition, RequirementResult, accept_claim,
    evaluate_acceptance, requirement_catalog,
};
use crucible_node_format::{BindingCompatibility, ContentRef, Id, canonical};

use super::{
    case::ReportCase,
    fixture::Gem5BehavioralRun,
    unit::{UnitMeasurement, encode},
};

const MAXIMUM_ORIGINAL_CASES: usize = 64;
const MAXIMUM_COLLECTED_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Retains source-authenticated original report data without accepted authority.
pub struct Gem5BehavioralReport {
    authority: OriginalReportAuthority,
    bytes: Vec<u8>,
    reference: ContentRef,
}

struct OriginalReportAuthority {
    unit: Arc<UnitMeasurement>,
    cases: Vec<ReportCase>,
    classes: BTreeSet<QualificationClass>,
    policy: (ContentRef, Vec<u8>),
    limitations: (ContentRef, Vec<u8>),
    claim: QualificationClaim,
    source_world: crucible_node_format::HashRef,
}

/// Owns accepted original evidence and exact source-selected admission bindings.
///
/// Construction remains private to successful independent ledger acceptance.
/// An accepted historical report still reopens current unit and original case
/// evidence at ordinary preparation and at final complete graph admission.
pub struct InstalledGem5BehavioralAcceptance {
    report: Arc<Gem5BehavioralReport>,
    bindings: BTreeMap<Id, BindingCompatibility>,
    classes: BTreeMap<Id, BTreeSet<QualificationClass>>,
    records: BTreeMap<Id, AcceptanceRecord>,
}

impl Gem5BehavioralRun {
    /// Retains every observed original and the complete unresolved RFC population.
    ///
    /// This operation does not retire or release this run. Actual native owners,
    /// runtime journals and publishers stay in the same source run during audit.
    ///
    /// # Errors
    /// Refuses changed installed source, original case scope drift, conflicting
    /// same-ID results, unknown body geometry or complete report credit exhaustion.
    ///
    /// # Panics
    /// An installed source reader may unwind. This method borrows the run; its
    /// runtime tokens and owners stay in that run, which the caller must retain.
    pub fn report(&self) -> Result<Gem5BehavioralReport, QualificationError> {
        self.unit().current()?;
        if self.cases().len() > MAXIMUM_ORIGINAL_CASES {
            return Err(QualificationError::Refused("original report case credit"));
        }
        let source_world = self.source_scenario().world.identity()?;
        // Charge both retained originals and the report-owned evidence copy before
        // copying any case. Tokens and native authority remain only in this run.
        let mut bytes = 64 * 1024u64;
        let mut seen = BTreeMap::new();
        for original in self.cases() {
            if original.world_binding_hash() != &source_world {
                return Err(QualificationError::Refused("foreign original case world"));
            }
            let (result, body) = original.result();
            result.verify(body)?;
            if let Some(prior) = seen.insert(original.id(), result)
                && prior != result
            {
                return Err(QualificationError::Refused(
                    "original same-ID case cannot be replaced",
                ));
            }
            for (reference, body) in original.objects() {
                reference.verify(body)?;
                bytes =
                    bytes
                        .checked_add(
                            reference.length.get().checked_mul(2).ok_or(
                                QualificationError::Refused("original/report copy overflow"),
                            )?,
                        )
                        .filter(|total| *total <= MAXIMUM_COLLECTED_BYTES)
                        .ok_or(QualificationError::Refused("complete original case bytes"))?;
            }
        }
        let mut classes = BTreeSet::new();
        for binding in &self.source_scenario().compatibility {
            classes.extend(
                super::super::super::acceptance::required_classes(self.source_scenario(), binding)
                    .map_err(evidence)?,
            );
        }
        let policy_bytes = encode(&(
            "crucible.gem5.behavioral-applicability.v1",
            self.unit().unit.clone(),
            &classes,
            "all compiled obligations are applicable until a separate exact source restriction authenticates exclusion; no missing case becomes NotApplicable",
        ))?;
        let policy = (
            canonical::content_ref(&policy_bytes, "application/json")?,
            policy_bytes,
        );
        let limitation_bytes = encode(&(
            "crucible.gem5.behavioral-limitations.v1",
            "fixed x86 freestanding source model; no CPU ingress; independent finite Script/Block; no Linux/device parity inferred; all absent adverse/continuation cases remain NotExecuted",
        ))?;
        let limitations = (
            canonical::content_ref(&limitation_bytes, "application/json")?,
            limitation_bytes,
        );
        let mut cases = Vec::new();
        cases
            .try_reserve_exact(self.cases().len())
            .map_err(evidence)?;
        for original in self.cases() {
            cases.push(ReportCase::from_original(original)?);
        }
        let mut requirements = Vec::new();
        let (catalog, ids) = requirement_catalog()?;
        requirements
            .try_reserve_exact(ids.len())
            .map_err(evidence)?;
        for id in ids {
            let observed: Vec<_> = cases
                .iter()
                .filter(|case| case.covers(id))
                .map(case_evidence)
                .collect();
            let disposition = if observed.is_empty() {
                RequirementDisposition::NotExecuted
            } else if observed
                .iter()
                .any(|case| case.verdict == CaseVerdict::Failed)
            {
                RequirementDisposition::Failed
            } else if observed
                .iter()
                .all(|case| case.verdict == CaseVerdict::Passed)
            {
                RequirementDisposition::Passed
            } else {
                RequirementDisposition::NotExecuted
            };
            requirements.push(RequirementResult {
                requirement: id.into(),
                disposition,
                cases: observed,
                not_applicable_reason: None,
            });
        }
        let claim = QualificationClaim {
            format: "crucible.node-qualification".into(),
            version: 1,
            unit: self.unit().unit.clone(),
            classes: classes.clone(),
            catalog,
            applicability_policy: policy.0.clone(),
            requirements,
            supersedes: None,
            limitations: limitations.0.clone(),
        };
        let encoded = encode(&claim)?;
        if encoded.len()
            > AcceptanceLimits::default()
                .qualification
                .maximum_claim_bytes
        {
            return Err(QualificationError::Refused(
                "complete original report extent",
            ));
        }
        let reference = canonical::content_ref(&encoded, "application/json")?;
        Ok(Gem5BehavioralReport {
            authority: OriginalReportAuthority {
                unit: self.unit().clone(),
                cases,
                classes,
                policy,
                limitations,
                claim,
                source_world,
            },
            bytes: encoded,
            reference,
        })
    }
}

impl Gem5BehavioralReport {
    /// Borrows immutable original bytes, including all unexecuted obligations.
    pub fn original(&self) -> (&ContentRef, &[u8]) {
        (&self.reference, &self.bytes)
    }

    /// Evaluates the original complete report without replacing unresolved cases.
    ///
    /// # Errors
    /// Refuses corrupt report encoding or changed independently measured source.
    /// Coverage failure is preserved in the returned Refused audit record.
    pub fn evaluate(&self) -> Result<Vec<u8>, QualificationError> {
        let current = self.authority.unit.current()?;
        let evaluated = evaluate_acceptance(
            &self.bytes,
            &self.reference,
            &current,
            &self.authority.classes,
            &self.authority,
            AcceptanceLimits::default(),
        )?;
        evaluated
            .record()
            .canonical_bytes(AcceptanceLimits::default().maximum_record_bytes)
    }

    /// Installs this original only after complete independent class acceptance.
    ///
    /// The caller keeps the original report and its collecting run. Installation
    /// into an idle target catalog does not retire the source or copy native
    /// authority. Its future ordinary scenario is independently regenerated.
    ///
    /// # Errors
    /// Refuses incomplete coverage, changed original scope or an occupied/already
    /// configured catalog. A refused install leaves this original report held.
    pub fn install(
        self: &Arc<Self>,
        catalog: &mut super::super::super::InstalledNodeCatalog,
        original_scenario: &crate::node_scenario::NodeScenario,
    ) -> Result<(), QualificationError> {
        let policy = self.enroll(original_scenario)?;
        catalog
            .install_behavioral_acceptance(Box::new(policy), AcceptanceLimits::default())
            .map_err(evidence)
    }

    /// Installs original accepted evidence for the same source-built four owners.
    ///
    /// # Errors
    /// Refuses any unresolved obligation, unsupported class, source drift or
    /// altered original source binding. A partial lawful report cannot enroll.
    pub(super) fn enroll(
        self: &Arc<Self>,
        scenario: &crate::node_scenario::NodeScenario,
    ) -> Result<InstalledGem5BehavioralAcceptance, QualificationError> {
        if scenario.world.identity()? != self.authority.source_world {
            return Err(QualificationError::Refused(
                "enrollment source world changed",
            ));
        }
        let current = self.authority.unit.current()?;
        accept_claim(
            &self.bytes,
            &self.reference,
            &current,
            &self.authority.classes,
            &self.authority,
            AcceptanceLimits::default().qualification,
        )?;
        let mut bindings = BTreeMap::new();
        let mut classes = BTreeMap::new();
        let mut records = BTreeMap::new();
        for original in &scenario.compatibility {
            let required = super::super::super::acceptance::required_classes(scenario, original)
                .map_err(evidence)?;
            let evaluated = evaluate_acceptance(
                &self.bytes,
                &self.reference,
                &current,
                &required,
                &self.authority,
                AcceptanceLimits::default(),
            )?;
            if evaluated.record().decision != AcceptanceDecision::Accepted {
                return Err(QualificationError::Refused("node original report refused"));
            }
            let bytes = evaluated
                .record()
                .canonical_bytes(AcceptanceLimits::default().maximum_record_bytes)?;
            let record = AcceptanceRecord::from_json(
                &bytes,
                AcceptanceLimits::default().maximum_record_bytes,
            )?;
            let mut binding = original.clone();
            binding.qualification_refs.push(self.reference.clone());
            binding.qualification_refs.sort();
            binding.qualification_refs.dedup();
            classes.insert(binding.node_id.clone(), required);
            records.insert(binding.node_id.clone(), record);
            bindings.insert(binding.node_id.clone(), binding);
        }
        Ok(InstalledGem5BehavioralAcceptance {
            report: self.clone(),
            bindings,
            classes,
            records,
        })
    }
}

impl InstalledAcceptancePolicy for InstalledGem5BehavioralAcceptance {
    fn scope_for_node(&self, node: &Id) -> Result<AcceptanceScope<'_>, QualificationError> {
        let current_unit = self.report.authority.unit.current()?;
        Ok(AcceptanceScope {
            binding: self
                .bindings
                .get(node)
                .ok_or(QualificationError::Refused("unenrolled ordinary gem5 node"))?,
            current_unit,
            required_classes: self
                .classes
                .get(node)
                .ok_or(QualificationError::Refused("node class source absent"))?
                .clone(),
            original_bytes: &self.report.bytes,
            original_claim: &self.report.reference,
            record: self.records.get(node).ok_or(QualificationError::Refused(
                "node original acceptance absent",
            ))?,
        })
    }
}

impl InstalledQualificationAuthority for OriginalReportAuthority {
    fn authenticate_claim(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        claim: &QualificationClaim,
    ) -> Result<(), QualificationError> {
        if claim != &self.claim
            || self.unit.current()? != claim.unit
            || encode(claim)? != bytes
            || canonical::content_ref(bytes, "application/json")? != *reference
        {
            return Err(QualificationError::Refused(
                "original source-issued report changed",
            ));
        }
        Ok(())
    }
    fn applicability(
        &self,
        unit: &QualificationUnit,
        classes: &BTreeSet<QualificationClass>,
        policy: &ContentRef,
    ) -> Result<BTreeMap<String, Applicability>, QualificationError> {
        if unit != &self.unit.current()? || classes != &self.classes || policy != &self.policy.0 {
            return Err(QualificationError::Refused(
                "unknown original applicability source",
            ));
        }
        Ok(requirement_catalog()?
            .1
            .into_iter()
            .map(|id| {
                (
                    id.into(),
                    Applicability::Applicable {
                        classes: classes.clone(),
                    },
                )
            })
            .collect())
    }
    fn verify_evidence(
        &self,
        reference: &ContentRef,
        maximum_bytes: u64,
        maximum_dependencies: usize,
    ) -> Result<Vec<ContentRef>, QualificationError> {
        if reference.length.get() > maximum_bytes {
            return Err(QualificationError::Refused("original evidence extent"));
        }
        for (identity, bytes) in [&self.policy, &self.limitations] {
            if reference == identity {
                reference.verify(bytes)?;
                let mut roots = Vec::new();
                if reference == &self.policy.0 {
                    roots
                        .try_reserve_exact(self.cases.len())
                        .map_err(evidence)?;
                    roots.extend(self.cases.iter().map(|case| case.result().0.clone()));
                    roots.sort();
                    roots.dedup();
                }
                if roots.len() > maximum_dependencies {
                    return Err(QualificationError::Refused(
                        "original evidence edge ceiling",
                    ));
                }
                return Ok(roots);
            }
        }
        if reference == &self.claim.catalog {
            let (identity, ids) = requirement_catalog()?;
            let body = ids.join("\n") + "\n";
            if &identity != reference {
                return Err(QualificationError::Refused("catalog identity changed"));
            }
            reference.verify(body.as_bytes())?;
            return Ok(Vec::new());
        }
        for case in &self.cases {
            if let Some((_, bytes)) = case
                .objects()
                .iter()
                .find(|(identity, _)| identity == reference)
            {
                reference.verify(bytes)?;
                let mut dependencies = if case.result().0 == reference {
                    case.objects()
                        .iter()
                        .map(|(identity, _)| identity.clone())
                        .filter(|identity| identity != reference)
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                dependencies.sort();
                dependencies.dedup();
                if dependencies.len() > maximum_dependencies {
                    return Err(QualificationError::Refused(
                        "original native body edge ceiling",
                    ));
                }
                return Ok(dependencies);
            }
        }
        self.unit
            .verify(reference, maximum_bytes, maximum_dependencies)
    }
    fn authenticate_case(
        &self,
        unit: &QualificationUnit,
        requirement: &str,
        case: &CaseEvidence,
    ) -> Result<(), QualificationError> {
        if unit != &self.unit.current()? {
            return Err(QualificationError::Refused("case unit changed"));
        }
        let original = self
            .cases
            .iter()
            .find(|original| original.id() == case.case && original.result().0 == &case.result)
            .ok_or(QualificationError::Refused(
                "case was never actually collected",
            ))?;
        if !original.covers(requirement)
            || case != &case_evidence(original)
            || original.world_binding_hash() != &self.source_world
        {
            return Err(QualificationError::Refused(
                "case has no complete source predicate coverage",
            ));
        }
        original.result().0.verify(original.result().1)?;
        original.oracle().0.verify(original.oracle().1)?;
        Ok(())
    }
}

impl InstalledQualificationAuthority for InstalledGem5BehavioralAcceptance {
    fn authenticate_claim(
        &self,
        r: &ContentRef,
        b: &[u8],
        c: &QualificationClaim,
    ) -> Result<(), QualificationError> {
        self.report.authority.authenticate_claim(r, b, c)
    }
    fn applicability(
        &self,
        u: &QualificationUnit,
        c: &BTreeSet<QualificationClass>,
        p: &ContentRef,
    ) -> Result<BTreeMap<String, Applicability>, QualificationError> {
        self.report.authority.applicability(u, c, p)
    }
    fn verify_evidence(
        &self,
        r: &ContentRef,
        b: u64,
        d: usize,
    ) -> Result<Vec<ContentRef>, QualificationError> {
        self.report.authority.verify_evidence(r, b, d)
    }
    fn authenticate_case(
        &self,
        u: &QualificationUnit,
        r: &str,
        c: &CaseEvidence,
    ) -> Result<(), QualificationError> {
        self.report.authority.authenticate_case(u, r, c)
    }
}

fn case_evidence(original: &ReportCase) -> CaseEvidence {
    CaseEvidence {
        case: original.id().into(),
        kind: CaseKind::RealizedProvider,
        verdict: original.verdict(),
        classes: BTreeSet::from([
            QualificationClass::BaseProvider,
            QualificationClass::RoleProfile,
            QualificationClass::ExactTiming,
        ]),
        result: original.result().0.clone(),
        oracle: original.oracle().0.clone(),
    }
}

fn evidence(error: impl std::fmt::Display) -> QualificationError {
    QualificationError::Evidence(error.to_string())
}
