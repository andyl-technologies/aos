//! Shared CLI policy rendering and distinct automation failure after a valid report.
//!
//! A policy failure leaves committed scan state unchanged. Its checked report is
//! already printed; the entry point must not append another JSON response.

use anyhow::Result;
use aos_assessment::report_policy::{
    AssessmentReportPolicyOutcomeV1, AssessmentReportPolicyV1, ReportFailureCondition,
};
use aos_core::output::{OutputMode, Printer};

use crate::cli::AssessmentFailureArg;

/// Indicates policy failure after a valid report, rather than failed execution.
#[derive(Debug)]
pub(crate) struct AssessmentPolicyFailure;

impl std::fmt::Display for AssessmentPolicyFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("selected assessment report policy failed")
    }
}

impl std::error::Error for AssessmentPolicyFailure {}

/// Normalizes explicit CLI selections without enabling implicit policy.
///
/// # Errors
/// Returns an error for an invalid normalized condition selection.
pub(crate) fn policy(
    selected: &[AssessmentFailureArg],
) -> Result<Option<AssessmentReportPolicyV1>> {
    if selected.is_empty() {
        return Ok(None);
    }
    let conditions = selected
        .iter()
        .map(|condition| match condition {
            AssessmentFailureArg::Coverage => ReportFailureCondition::Coverage,
            AssessmentFailureArg::Updates => ReportFailureCondition::Updates,
            AssessmentFailureArg::Vulnerabilities => ReportFailureCondition::Vulnerabilities,
        })
        .collect();
    Ok(Some(AssessmentReportPolicyV1::new(conditions)?))
}

/// Completes an already rendered valid report with its independent policy exit.
///
/// # Errors
/// Returns the distinct policy-failure marker when a selected condition matched.
pub(crate) fn finish(
    printer: &Printer,
    force_json: bool,
    outcome: Option<&AssessmentReportPolicyOutcomeV1>,
) -> Result<()> {
    let Some(outcome) = outcome else {
        return Ok(());
    };
    if !force_json && printer.mode() != OutputMode::Json {
        printer.info(&format!(
            "Report policy: {}",
            if outcome.failed { "fail" } else { "pass" }
        ));
    }
    if outcome.failed {
        return Err(AssessmentPolicyFailure.into());
    }
    Ok(())
}
