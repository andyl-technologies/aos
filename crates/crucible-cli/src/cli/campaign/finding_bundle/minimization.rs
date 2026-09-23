//! Authenticated minimization outcome rendered from a retained finding trace.

use serde::Serialize;

use super::*;

#[derive(Serialize)]
pub(super) struct FindingBundleMinimizationReport {
    pub(super) disposition: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) retained: Option<RetainedFindingMinimizationReport>,
}

impl FindingBundleMinimizationReport {
    pub(super) fn table_summary(&self) -> String {
        match &self.retained {
            Some(retained) => format!(
                "minimization={} original-reproduction={} minimized-reproduction={} policy-schema={} original-decisions={} minimized-decisions={} original-selections={} minimized-selections={} candidates={}{}",
                self.disposition,
                retained.original_reproduction,
                retained.minimized_reproduction,
                retained.policy_schema,
                retained.original_schedule_decisions,
                retained.minimized_schedule_decisions,
                retained.original_selections,
                retained.minimized_selections,
                retained.attempts.len(),
                self.reason
                    .as_ref()
                    .map_or(String::new(), |reason| format!(" reason={reason:?}")),
            ),
            None => format!("minimization={}", self.disposition),
        }
    }

    pub(super) fn markdown_rows(&self) -> String {
        let mut rows = format!("\n| minimization | `{}` |", self.disposition);
        if let Some(retained) = &self.retained {
            rows.push_str(&format!(
                "\n| original reproduction | `{}` |\n| minimized reproduction | `{}` |\n| minimization policy schema | {} |\n| original decisions | {} |\n| minimized decisions | {} |\n| original selections | {} |\n| minimized selections | {} |\n| candidate attempts | {} |",
                retained.original_reproduction,
                retained.minimized_reproduction,
                retained.policy_schema,
                retained.original_schedule_decisions,
                retained.minimized_schedule_decisions,
                retained.original_selections,
                retained.minimized_selections,
                retained.attempts.len(),
            ));
        }
        if let Some(reason) = &self.reason {
            rows.push_str(&format!("\n| no-reduction reason | {} |", reason));
        }
        rows
    }
}

#[derive(Serialize)]
pub(super) struct RetainedFindingMinimizationReport {
    pub(super) original_reproduction: String,
    pub(super) minimized_reproduction: String,
    pub(super) policy_schema: u32,
    pub(super) original_schedule_decisions: usize,
    pub(super) minimized_schedule_decisions: usize,
    pub(super) original_selections: usize,
    pub(super) minimized_selections: usize,
    pub(super) schedule_reduced: bool,
    pub(super) attempts: Vec<FindingMinimizationAttemptReport>,
}

#[derive(Serialize)]
pub(super) struct FindingMinimizationAttemptReport {
    sequence: u64,
    candidate_artifact: String,
    candidate_schedule: String,
    replayed_state: String,
    observed_fingerprint: Option<String>,
    accepted: bool,
    outcome: &'static str,
}

pub(super) fn finding_bundle_minimization_report(
    finding: &crate::cli_report::CampaignTriageFindingEvidence,
) -> Result<FindingBundleMinimizationReport, CliError> {
    let Some(minimized) = finding.minimized_reproduction.as_ref() else {
        return Ok(FindingBundleMinimizationReport {
            disposition: "not-retained",
            reason: None,
            retained: None,
        });
    };
    let trace = minimized.minimization().ok_or_else(|| {
        backend_error("retained minimized reproduction has no minimization trace")
    })?;
    let original_id = finding
        .reproduction
        .id()
        .map_err(|error| backend_error(format!("original reproduction ID is invalid: {error}")))?;
    let minimized_id = minimized
        .id()
        .map_err(|error| backend_error(format!("minimized reproduction ID is invalid: {error}")))?;
    if trace.original() != original_id {
        return Err(backend_error(
            "retained minimization trace names another original reproduction",
        ));
    }

    let original_schedule = schedule_counts(&finding.reproduction)?;
    let minimized_schedule = schedule_counts(minimized)?;
    let target = finding.finding.signature().fingerprint();
    let attempts = trace
        .attempts()
        .iter()
        .map(|attempt| {
            let outcome = match (attempt.accepted(), attempt.observed_fingerprint()) {
                (true, _) => "accepted",
                (false, None) => "no-fingerprint",
                (false, Some(fingerprint)) if fingerprint != target => "different-fingerprint",
                (false, Some(_)) => "not-accepted",
            };
            FindingMinimizationAttemptReport {
                sequence: attempt.sequence(),
                candidate_artifact: attempt.candidate_artifact().to_hex(),
                candidate_schedule: attempt.candidate_schedule().to_hex(),
                replayed_state: attempt.replayed_state().to_hex(),
                observed_fingerprint: attempt.observed_fingerprint().map(|hash| hash.to_hex()),
                accepted: attempt.accepted(),
                outcome,
            }
        })
        .collect::<Vec<_>>();
    let accepted = attempts.iter().any(|attempt| attempt.accepted);
    if !accepted && minimized_schedule.0 < original_schedule.0 {
        return Err(backend_error(
            "retained minimization reduced the schedule without an accepted candidate",
        ));
    }
    let reason = if accepted {
        None
    } else if attempts.is_empty() && original_schedule.0 == 0 {
        Some(String::from(
            "original schedule has no recorded decisions to remove",
        ))
    } else if attempts.is_empty() {
        Some(String::from(
            "retained minimization trace records no candidate attempts; policy-specific exclusion is not encoded in this report",
        ))
    } else {
        let without_fingerprint = attempts
            .iter()
            .filter(|attempt| attempt.outcome == "no-fingerprint")
            .count();
        let different_fingerprint = attempts
            .iter()
            .filter(|attempt| attempt.outcome == "different-fingerprint")
            .count();
        let not_accepted = attempts
            .iter()
            .filter(|attempt| attempt.outcome == "not-accepted")
            .count();
        Some(format!(
            "{} candidates rejected: {without_fingerprint} without a failure fingerprint, {different_fingerprint} with a different fingerprint, {not_accepted} with the target fingerprint but not accepted",
            attempts.len(),
        ))
    };
    Ok(FindingBundleMinimizationReport {
        disposition: if accepted {
            "candidate-accepted"
        } else {
            "no-reduction"
        },
        reason,
        retained: Some(RetainedFindingMinimizationReport {
            original_reproduction: original_id.to_string(),
            minimized_reproduction: minimized_id.to_string(),
            policy_schema: trace.policy_schema(),
            original_schedule_decisions: original_schedule.0,
            minimized_schedule_decisions: minimized_schedule.0,
            original_selections: original_schedule.1,
            minimized_selections: minimized_schedule.1,
            schedule_reduced: minimized_schedule.0 < original_schedule.0,
            attempts,
        }),
    })
}

fn schedule_counts(
    reproduction: &crucible_campaign::ReproductionArtifact,
) -> Result<(usize, usize), CliError> {
    let artifact = crucible::ReproductionArtifact::from_compact_binary(reproduction.payload())
        .map_err(|error| backend_error(format!("finding schedule is invalid: {error}")))?;
    let decisions = artifact.schedule().decisions();
    let selections = decisions
        .iter()
        .filter(|decision| matches!(decision, crucible::Decision::Selection(_)))
        .count();
    Ok((decisions.len(), selections))
}
