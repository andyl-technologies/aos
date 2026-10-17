//! Defines the immutable complete Clock population before its original Arm.
//!
//! Existing exact/state evidence covers only its listed observations. Missing
//! activation-failure and damaged-restore experiments remain required originals;
//! no source label, successful serializer or timing case marks those passed.

use std::collections::{BTreeMap, BTreeSet};

use crate::node_observed_executor::factory::execution_text;

use crate::node_qualification::{
    CaseKind, PlannedFixtureAudit, PlannedWitnessCase, QualificationClass, QualificationLimits,
    WitnessCriterion, WitnessPlan, requirement_catalog,
};

use super::*;

pub(super) const IDENTITY: &str = "clock/installed-source-identity";
pub(super) const ADVERSE: &str = "clock/two-owner-readiness-and-completion-loss";
pub(super) const STATE: &str = "clock/state-and-repeatability";
pub(super) const BEFORE_COMMIT_FAILURE: &str = "clock/failed-publication-before-commit";
pub(super) const AFTER_COMMIT_FAILURE: &str = "clock/failed-publication-after-commit";
pub(super) const DAMAGED_RESTORE: &str = "clock/damaged-restoration-refusals";

pub(super) struct Population {
    pub(super) plan: WitnessPlan,
    pub(super) reference: ContentRef,
    pub(super) bytes: Vec<u8>,
    pub(super) content: BTreeMap<ContentRef, Vec<u8>>,
    pub(super) audit: PlannedFixtureAudit,
}

pub(super) fn classes() -> BTreeSet<QualificationClass> {
    use QualificationClass::*;
    BTreeSet::from([
        BaseProvider,
        ExactTiming,
        RoleProfile,
        Repeatable,
        CaptureModeledLive,
        CaptureModeledDurable,
    ])
}

pub(super) fn exact_classes() -> BTreeSet<QualificationClass> {
    use QualificationClass::*;
    BTreeSet::from([BaseProvider, ExactTiming, RoleProfile])
}

impl Population {
    pub(super) fn new(
        unit: &unit::Unit,
        original: &OriginalClockQualificationRun,
        adverse_executions: [ExecutionId; 2],
        publication_executions: [ExecutionId; 2],
    ) -> Result<Self, QualificationError> {
        let mut content = BTreeMap::new();
        let mut cases = Vec::new();
        for (name, oracle) in original.case_oracles_data() {
            cases.push(PlannedWitnessCase {
                id: name.to_owned(),
                kind: CaseKind::RealizedProvider,
                classes: exact_classes(),
                oracle: oracle.reference.clone(),
            });
        }
        cases.push(PlannedWitnessCase {
            id: STATE.to_owned(),
            kind: CaseKind::RealizedProvider,
            classes: classes(),
            oracle: unit.state_oracle.clone(),
        });
        let adverse = unit::retain(
            &mut content,
            &(
                "crucible.normal-clock-adverse-oracle/1",
                &unit.value,
                adverse_executions.map(execution_text),
                "two real independent Clock owners; withheld second readiness; actual ordinary activation refused; both gates closed without advancement",
                "separate genuinely committed world; first full native effect and ACK remain; second actual completed outcome lost before commit and retained Unknown; affected owner contained and committed world unchanged",
                "subset only; does not discharge complete publication-failure/recovery or damaged-restoration obligations",
            ),
        )?;
        cases.push(PlannedWitnessCase {
            id: ADVERSE.to_owned(),
            kind: CaseKind::RealizedProvider,
            classes: BTreeSet::from([QualificationClass::BaseProvider]),
            oracle: adverse,
        });
        let identity = unit::retain(
            &mut content,
            &(
                "crucible.normal-clock-source-inspection/1",
                &unit.value,
                "actual current process/thread/executable/kernel; complete source-selected descriptor, owner, contract, guarantee and empty-port inventory; no claim from a parsed Accepted label",
            ),
        )?;
        cases.push(PlannedWitnessCase {
            id: IDENTITY.to_owned(),
            kind: CaseKind::SourceInspection,
            classes: BTreeSet::from([QualificationClass::BaseProvider]),
            oracle: identity,
        });
        for (name, property) in [
            (
                BEFORE_COMMIT_FAILURE,
                "actual complete publication refuses before commitment; original prepared owner and first coordinator bank retained; no execution gate or semantic mutation",
            ),
            (
                AFTER_COMMIT_FAILURE,
                "actual uncertain or failed publication preserves original committed/unknown knowledge, first bank and native custody; no rollback claim or replacement retry",
            ),
            (
                DAMAGED_RESTORE,
                "actual native archive refuses corrupt, missing, changed-codec and stale source/owner closure before fresh execution; original source and refusal owners retained",
            ),
        ] {
            let oracle = unit::retain(
                &mut content,
                &(
                    "crucible.normal-clock-required-original/1",
                    name,
                    property,
                    &unit.value,
                    publication_executions.map(execution_text),
                ),
            )?;
            cases.push(PlannedWitnessCase {
                id: name.to_owned(),
                kind: CaseKind::RealizedProvider,
                classes: if name == DAMAGED_RESTORE {
                    BTreeSet::from([
                        QualificationClass::CaptureModeledLive,
                        QualificationClass::CaptureModeledDurable,
                    ])
                } else {
                    BTreeSet::from([QualificationClass::BaseProvider])
                },
                oracle,
            });
        }
        cases.sort_by(|a, b| a.id.cmp(&b.id));
        let (catalog, ids) = requirement_catalog()?;
        unit::insert(
            &mut content,
            catalog,
            format!("{}\n", ids.join("\n")).into_bytes(),
        )?;
        let mut requirements = BTreeMap::new();
        for id in ids {
            // A full normal gate still owns every obligation. This initial
            // complete population deliberately requires the adverse originals
            // as well as positive native cases; omission never becomes NA.
            let names = cases.iter().map(|case| case.id.clone()).collect::<Vec<_>>();
            let criterion = unit::retain(
                &mut content,
                &(
                    "crucible.normal-clock-required-criterion/1",
                    id,
                    &unit.value.specification,
                    &names,
                    "all declared original suites required; exact/role and live/durable/repeatable axes stay distinct; no backend-specific exclusion",
                ),
            )?;
            requirements.insert(
                id.to_owned(),
                WitnessCriterion::Applicable {
                    cases: names,
                    criterion,
                },
            );
        }
        let limitations = unit::retain(
            &mut content,
            &(
                "crucible.normal-clock-limitations/1",
                "portless integer Clock only; same measured source and actual aggregate enforcement; no guest CPU/device or scientific accuracy claim",
                "all six source-derived classes required; missing publication-failure or damaged-restore originals retain NotExecuted and prevent normal enrollment",
                "calibration runtime never installed as mixed-world native authority; ordinary installed source and complete-world admission remain separate",
            ),
        )?;
        let plan = WitnessPlan {
            schema: "crucible.node-witness-plan.v1".to_owned(),
            unit: unit.value.clone(),
            classes: classes(),
            requirements,
            cases,
            limitations,
        };
        let reference = unit::retain(&mut content, &plan)?;
        let bytes = content
            .get(&reference)
            .ok_or(reject("Clock original plan body absent"))?
            .clone();
        let audit = PlannedFixtureAudit::prepare(
            &plan,
            &reference,
            QualificationLimits::default(),
            4 * 1024 * 1024,
        )?;
        Ok(Self {
            plan,
            reference,
            bytes,
            content,
            audit,
        })
    }
}
