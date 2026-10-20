//! Renders authenticated resume execution into the CLI outcome contract.

use super::*;

pub(crate) fn finish_resume_workflow_outcome(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    resume_plan: &ResumeInvocationPlan,
    report: ResumeWorkflowReport,
) -> Result<BackendCommandOutcome, CliError> {
    let mut outcome = backend_command_outcome(thin_plan, backend_plan, ergonomics_plan);
    let oracle = report.terminal_oracle.clone();
    outcome.status = report.run.status;
    outcome.exit_code = report.run.status.exit_code();
    outcome.terminal_savepoint = report.run.terminal_savepoint;
    outcome.stdout.push(format!(
        "resume-session\tcheckpoint={}\tconfiguration={}\tscenario={}\tfinal={}\toutcome={}\tfrontier_ticks={}\tquanta={}\tacks={}",
        format_content_hash_ref(report.source_checkpoint),
        format_content_hash_ref(report.resumed_configuration),
        report.scenario_label,
        report.run.final_state,
        terminal_outcome_label(report.run.outcome),
        report.run.final_frontier_ticks,
        report.run.final_quanta,
        report.run.acknowledged_commands.len()
    ));
    for status in &report.run.watch_statuses {
        outcome.stdout.push(format!("run-watch\t{status}"));
    }
    outcome.stdout.push(format!(
        "resume-oracle\tstatus={}\tconfiguration={}\tfat={}\tthin={}",
        oracle.status_label(),
        format_content_hash_ref(oracle.configuration),
        format_content_hash_ref(oracle.fat_checkpoint),
        format_content_hash_ref(oracle.thin_checkpoint)
    ));
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("session"),
        kind: String::from("resume_checkpoint"),
        summary: format!(
            "checkpoint={} configuration={} until={}",
            format_content_hash_ref(report.source_checkpoint),
            format_content_hash_ref(report.resumed_configuration),
            resume_plan.terminal_condition.label()
        ),
    });
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("replay-oracle"),
        kind: String::from("resume_oracle_validation"),
        summary: format!(
            "status={} configuration={} fat={} thin={}",
            oracle.status_label(),
            format_content_hash_ref(oracle.configuration),
            format_content_hash_ref(oracle.fat_checkpoint),
            format_content_hash_ref(oracle.thin_checkpoint)
        ),
    });
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
    outcome.savepoint_oracle = Some(oracle);
    Ok(outcome)
}
