//! Shared human rendering of exact local and hosted advisory projections.

use aos_assessment_runtime::advisories::AdvisoryPageV1;
use aos_core::output::Printer;
use aos_maintain::presentation::escape_terminal;

/// Renders a validated retained-revision page without treating missing evidence as clean.
pub(in crate::commands) fn render_advisory(printer: &Printer, page: &AdvisoryPageV1) {
    let escape = |value: &str| escape_terminal(value, 4096);
    printer.info(&format!(
        "{}: retained evidence at {}",
        escape(&page.advisory_id),
        page.as_of
    ));
    printer.info("This lookup does not establish current affected or clean status.");
    if let Some(context) = &page.assessment_context {
        printer.info(&format!(
            "Historical assessment {} · evaluated {} · snapshot {}",
            context.assessment_digest, context.evaluated_at, context.snapshot_digest
        ));
    }
    if page.revisions.is_empty() {
        printer.info("No matching retained revisions in the selected scope.");
    }
    for revision in &page.revisions {
        let record = &revision.record;
        printer.info(&format!(
            "{} · {} · modified {} · {}",
            escape(&record.provider),
            escape(&record.id),
            escape(&record.modified),
            revision.record_digest
        ));
        if let Some(withdrawn) = &record.withdrawn {
            printer.info(&format!("Withdrawn at {}", escape(withdrawn)));
        }
        printer.info(&escape(&record.summary));
        for severity in &record.severity {
            printer.info(&format!(
                "Severity {} / {}: {}",
                escape(&severity.source),
                escape(&severity.scheme),
                escape(&severity.value)
            ));
        }
        for link in &revision.finding_links {
            printer.info(&format!(
                "Finding {} · {} / {} · {:?}",
                link.finding_key,
                escape(&link.subject_ref),
                escape(&link.component_ref),
                link.applicability
            ));
        }
    }
    if let Some(next) = page.next_record {
        printer.info(&format!("Continue with --resource-scope {} --after-record {} and the same advisory and assessment selection.", escape(&page.resource_scope), next));
    }
}
