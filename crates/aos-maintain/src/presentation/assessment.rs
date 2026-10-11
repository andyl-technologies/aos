//! Shared human assessment output for local maintenance and Hub clients.

use aos_assessment::result::SubjectResult;

use super::escape_terminal;

/// Renders one subject with identical profile, finding and version detail.
///
/// Callers supply an authorized package label or the portable subject reference.
/// Terminal controls in externally supplied labels and advisory IDs are escaped.
#[must_use]
pub fn assessment_subject_lines(subject: &SubjectResult, label: &str) -> Vec<String> {
    let mut lines = vec![escape_terminal(label, 4096)];
    for coverage in &subject.coverage {
        lines.push(format!(
            "  {:?}: {:?}; {} of {} components evaluated",
            coverage.profile, coverage.state, coverage.counts.evaluated, coverage.counts.declared
        ));
    }
    for finding in &subject.findings {
        lines.push(format!(
            "  {}: {:?}",
            escape_terminal(&finding.advisory_ids.join(", "), 4096),
            finding.applicability
        ));
    }
    for version in &subject.versions {
        lines.push(format!(
            "  {}: {:?}",
            escape_terminal(&version.current.comparison_version, 4096),
            version.decision
        ));
    }
    lines
}
