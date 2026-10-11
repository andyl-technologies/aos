//! Rechecks installed scope at connection boundaries and verifies original reports.

use std::collections::BTreeSet;
use std::io::{self, Write};

use crucible_node_contract::{ContentRef, HashRef, Id, canonical};
use crucible_node_provider::ProviderError;
use crucible_node_provider::conformance::{
    CheckDisposition, ConformanceReport, ProbeConnector, ProbePlan, ProbeSession,
    UnixProbeConnector,
};
use serde::Serialize;

use super::{InstalledConformanceAuthority, ProtocolCase};
use crate::node_qualification::{
    Applicability, QualificationClass, QualificationError, QualificationLimits, QualificationUnit,
    WitnessCriterion, WitnessPlan,
};

pub(super) fn check_applicability(
    authority: &dyn InstalledConformanceAuthority,
    plan: &WitnessPlan,
    reference: &ContentRef,
) -> Result<(), QualificationError> {
    let current = authority.applicability(&plan.unit, &plan.classes, reference)?;
    if current.len() != plan.requirements.len() {
        return Err(QualificationError::Refused(
            "incomplete installed collection applicability",
        ));
    }
    for (requirement, criterion) in &plan.requirements {
        let matches = match (current.get(requirement), criterion) {
            (
                Some(Applicability::NotApplicable { reason }),
                WitnessCriterion::NotApplicable {
                    reason: declared, ..
                },
            ) => reason == declared,
            (
                Some(Applicability::Applicable { classes }),
                WitnessCriterion::Applicable { cases, .. },
            ) => {
                let mut coverage = BTreeSet::new();
                for case in cases {
                    let original = plan
                        .cases
                        .iter()
                        .find(|planned| planned.id == *case)
                        .ok_or(QualificationError::Refused(
                            "unknown original applicability case",
                        ))?;
                    coverage.extend(original.classes.iter().copied());
                }
                !classes.is_empty() && coverage == *classes
            }
            _ => false,
        };
        if !matches {
            return Err(QualificationError::Refused(
                "changed required collection coverage",
            ));
        }
    }
    Ok(())
}

pub(super) fn current_scope(
    authority: &dyn InstalledConformanceAuthority,
    node: &Id,
    binding: &HashRef,
    unit: &QualificationUnit,
    classes: &BTreeSet<QualificationClass>,
) -> Result<(), QualificationError> {
    let scope = authority.scope_for_node(node)?;
    if scope.binding.node_id != *node
        || scope.binding.identity()? != *binding
        || scope.current_unit != *unit
        || scope.required_classes != *classes
    {
        return Err(QualificationError::Refused(
            "changed installed conformance scope",
        ));
    }
    Ok(())
}

pub(super) fn precharge(value: &impl Serialize, ceiling: usize) -> Result<(), QualificationError> {
    encoded_size(value, ceiling).map(|_| ())
}

pub(super) fn encoded_size(
    value: &impl Serialize,
    ceiling: usize,
) -> Result<usize, QualificationError> {
    let mut budget = Budget(ceiling);
    serde_json::to_writer(&mut budget, value)
        .map_err(|_| QualificationError::Refused("conformance serialized byte ceiling"))?;
    Ok(ceiling - budget.0)
}

pub(super) fn report_credit(plan: &ProbePlan) -> Result<usize, QualificationError> {
    plan.steps
        .len()
        .checked_add(1)
        .and_then(|count| count.checked_mul(8192))
        .ok_or(QualificationError::Refused(
            "protocol report credit overflow",
        ))
}

pub(super) fn check_plan(
    case: &ProtocolCase,
    limits: QualificationLimits,
) -> Result<(), QualificationError> {
    // A complete worst-case report is credited before the first connection,
    // including one measured endpoint per step and escaped case/diagnostic text.
    let required = report_credit(&case.plan)?;
    if required > limits.maximum_claim_bytes || required as u64 > limits.maximum_evidence_bytes {
        return Err(QualificationError::Refused(
            "protocol report pre-effect credit",
        ));
    }
    precharge(&case.plan, limits.maximum_claim_bytes)?;
    case.plan.validate().map_err(provider_failure)?;
    let bytes = canonical::canonical_json(
        &serde_json::to_value(&case.plan).map_err(crucible_node_contract::ContractError::from)?,
    )?;
    case.oracle.verify(&bytes)?;
    Ok(())
}

pub(super) fn check_report(
    plan: &ProbePlan,
    report: &ConformanceReport,
    executable: &ContentRef,
    uid: u64,
) -> Result<(), QualificationError> {
    let plan_identity = canonical::json_hash(
        "cnp.conformance-plan.v1",
        &serde_json::to_value(plan).map_err(crucible_node_contract::ContractError::from)?,
    )?;
    if report.schema_version != 1
        || !report.protocol_only
        || report.harness != "crucible-node-conformance.protocol-v1"
        || report.fixture != plan.fixture
        || report.plan_identity != plan_identity
        || report.results.len() != plan.steps.len()
    {
        return Err(QualificationError::Refused(
            "changed original protocol report",
        ));
    }
    let mut observed = BTreeSet::new();
    let mut dependent_failure = false;
    for (step, result) in plan.steps.iter().zip(&report.results) {
        if result.case != *step.id()
            || result.check != step.check()
            || (dependent_failure && result.disposition != CheckDisposition::NotExecuted)
        {
            return Err(QualificationError::Refused(
                "rewritten protocol case population",
            ));
        }
        match result.disposition {
            CheckDisposition::Passed => {
                if let Some(check) = result.check {
                    observed.insert(check);
                }
            }
            CheckDisposition::Failed => dependent_failure = true,
            CheckDisposition::NotExecuted => {
                if !dependent_failure {
                    return Err(QualificationError::Refused("unexplained protocol omission"));
                }
            }
        }
    }
    let missing: BTreeSet<_> = plan
        .required_checks
        .difference(&observed)
        .copied()
        .collect();
    if report.missing_checks != missing
        || report.endpoints.iter().any(|peer| {
            peer.peer_pid.get() == 0 || peer.peer_uid.get() != uid || peer.executable != *executable
        })
        || (report
            .results
            .iter()
            .any(|row| row.disposition == CheckDisposition::Passed && row.check.is_some())
            && report.endpoints.is_empty())
    {
        return Err(QualificationError::Refused(
            "missing or changed endpoint/check witness",
        ));
    }
    Ok(())
}

pub(super) struct ScopedConnector<'a> {
    pub underlying: &'a mut UnixProbeConnector,
    pub authority: &'a dyn InstalledConformanceAuthority,
    pub node: &'a Id,
    pub binding: &'a HashRef,
    pub unit: &'a QualificationUnit,
    pub classes: &'a BTreeSet<QualificationClass>,
    pub peer_executable: &'a ContentRef,
    pub peer_uid: u64,
}

impl ProbeConnector for ScopedConnector<'_> {
    fn connect(&mut self) -> Result<Box<dyn ProbeSession>, ProviderError> {
        current_scope(
            self.authority,
            self.node,
            self.binding,
            self.unit,
            self.classes,
        )
        .map_err(scope_failure)?;
        let mut session = self.underlying.connect()?;
        let matches = session.measurement().is_some_and(|peer| {
            peer.peer_pid.get() != 0
                && peer.peer_uid.get() == self.peer_uid
                && peer.executable == *self.peer_executable
        });
        if !matches {
            session.fence();
            return Err(ProviderError::Correlation(
                "unmeasured or changed conformance peer",
            ));
        }
        // ProbeSession is owned and has a 'static API. Scope is rechecked by the
        // connector at reconnect and by the runner before and after collection;
        // current native authority is independently checked by every provider
        // method. No borrowed policy is erased into an unbounded lifetime.
        Ok(session)
    }
}

fn provider_failure(error: ProviderError) -> QualificationError {
    QualificationError::Evidence(error.to_string())
}

fn scope_failure(_: QualificationError) -> ProviderError {
    ProviderError::Correlation("current installed conformance scope refused")
}

struct Budget(usize);

impl Write for Budget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("conformance encoding credit"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
