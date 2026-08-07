//! Replay report rendering and canonical machine-readable summaries.

use super::*;

pub(super) fn emit_replay_report_output(
    cli: &Cli,
    report: &ReplayArtifactReport,
) -> Result<(), CliError> {
    let format = cli.output_format();
    if format.is_machine_readable() {
        let status = replay_report_status(report);
        let exit_code = replay_report_exit_code(report);
        let entries = replay_machine_readable_trace_entries(report, status, exit_code);
        emit_canonical_trace(format, &entries, cli.trace.as_deref(), !cli.quiet)?;
    } else if !cli.quiet {
        write_replay_report_human(&mut io::stdout(), report)?;
    }
    Ok(())
}
pub(super) fn emit_replay_error_output(
    cli: &Cli,
    args: &ReplayArgs,
    error: &CliError,
) -> Result<(), CliError> {
    let format = cli.output_format();
    if !format.is_machine_readable() {
        return Ok(());
    }

    let mut entries = Vec::new();
    push_replay_trace_entry(
        &mut entries,
        "replay_error",
        format!("path={} error={error}", args.artifact.display()),
    );
    let canonical_log_digest = canonical_log_digest(&entries);
    push_replay_trace_entry(
        &mut entries,
        "final_outcome",
        format!(
            "subcommand=replay status=failed exit_code={} canonical_log={} artifact=unavailable",
            error.exit_code(),
            canonical_log_digest
        ),
    );
    emit_canonical_trace(format, &entries, cli.trace.as_deref(), !cli.quiet)?;
    Ok(())
}

pub(super) fn replay_report_status(report: &ReplayArtifactReport) -> BackendCommandStatus {
    if report
        .check
        .as_ref()
        .and_then(|check| check.mismatch.as_ref())
        .is_some()
    {
        return BackendCommandStatus::Failed;
    }
    if report
        .bisect
        .as_ref()
        .and_then(|bisect| bisect.divergence.as_ref())
        .is_some()
    {
        BackendCommandStatus::Failed
    } else {
        BackendCommandStatus::Passed
    }
}

pub(super) fn replay_report_exit_code(report: &ReplayArtifactReport) -> i32 {
    replay_report_status(report).exit_code()
}

pub(super) fn replay_machine_readable_trace_entries(
    report: &ReplayArtifactReport,
    status: BackendCommandStatus,
    exit_code: i32,
) -> Vec<CanonicalLogEntry> {
    let mut entries = Vec::new();
    push_replay_trace_entry(
        &mut entries,
        "replay_artifact",
        format!(
            "path={} digest={} seed={} scenario={}",
            report.path.display(),
            report.digest,
            report.seed,
            report.scenario_digest
        ),
    );
    if let Some(reduction) = &report.reduction {
        push_replay_trace_entry(
            &mut entries,
            "replay_reduction",
            format!(
                "status=reexecuted artifact={} scenario={} schedule={} state={} reconstructed_decisions={}",
                format_content_hash_ref(reduction.artifact),
                format_content_hash_ref(reduction.scenario),
                format_content_hash_ref(reduction.schedule),
                format_content_hash_ref(reduction.state),
                reduction.reconstructed_decisions
            ),
        );
    }
    if let Some(live) = &report.live_qemu {
        push_replay_trace_entry(
            &mut entries,
            "replay_live_qemu",
            format!(
                "validation=passed producer={} reproduced_status={} reproduced_outcome={} terminal_configuration={} event_stream={} fingerprint_stream={} controls={}",
                live.producer,
                live.terminal_status,
                live.terminal_outcome,
                live.terminal_configuration,
                live.event_stream_digest,
                live.fingerprint_stream_digest,
                live.controls
            ),
        );
    }
    if let Some(check) = &report.check {
        push_replay_trace_entry(
            &mut entries,
            "replay_check",
            replay_check_machine_readable_summary(check),
        );
    }
    if let Some(target) = &report.to_savepoint {
        push_replay_trace_entry(
            &mut entries,
            "replay_to_savepoint",
            replay_to_savepoint_machine_readable_summary(target),
        );
    }
    if let Some(bisect) = &report.bisect {
        push_replay_trace_entry(
            &mut entries,
            "replay_bisect",
            replay_bisect_machine_readable_summary(bisect),
        );
    }
    let canonical_log_digest = canonical_log_digest(&entries);
    push_replay_trace_entry(
        &mut entries,
        "final_outcome",
        replay_final_outcome_summary(report, status, exit_code, &canonical_log_digest),
    );
    entries
}

pub(super) fn push_replay_trace_entry(
    entries: &mut Vec<CanonicalLogEntry>,
    kind: impl Into<String>,
    summary: impl Into<String>,
) {
    entries.push(CanonicalLogEntry {
        sequence: entries.len() as u64,
        virtual_time_ticks: entries
            .last()
            .map(|entry| entry.virtual_time_ticks.saturating_add(1))
            .unwrap_or(0),
        node: String::from("cli"),
        kind: kind.into(),
        summary: summary.into(),
    });
}

pub(super) fn replay_final_outcome_summary(
    report: &ReplayArtifactReport,
    status: BackendCommandStatus,
    exit_code: i32,
    canonical_log_digest: &str,
) -> String {
    format!(
        "subcommand=replay status={} exit_code={} canonical_log={} artifact={}",
        status.label(),
        exit_code,
        canonical_log_digest,
        report.digest
    )
}

pub(super) fn replay_check_machine_readable_summary(check: &ReplayCheckReport) -> String {
    match &check.mismatch {
        Some(mismatch) => format!(
            "path={} status=mismatch expected={} replayed={} first_diff_byte={} original_len={} replayed_len={}",
            check.path.display(),
            mismatch.original_digest,
            mismatch.replayed_digest,
            mismatch.first_diff_byte,
            mismatch.original_len,
            mismatch.replayed_len
        ),
        None => format!(
            "path={} status=byte-identical digest={}",
            check.path.display(),
            check.digest
        ),
    }
}

pub(super) fn replay_to_savepoint_machine_readable_summary(
    target: &ReplayToSavepointReport,
) -> String {
    format!(
        "target={} status=target-validated schedule_prefix=typed materialization={} unified_operation={} checkpoint={} frontier_ticks={} target_decisions={} artifact_decisions={} matched_decisions={} typed_prefix_digest={} artifact_prefix_digest={} materialized_configuration={} materialized_schedule={} materialized_checkpoint={} runtime_state={} reduced_state={} single_vm_fingerprint={} graph={} replay_fat={} replay_thin={} oracle={} store_objects={}",
        target.target_label,
        target.materialization.materialization,
        target.materialization.operation,
        format_content_hash_ref(target.checkpoint),
        target.frontier_ticks,
        target.schedule_prefix.target_decisions,
        target.schedule_prefix.artifact_decisions,
        target.schedule_prefix.matched_decisions,
        target.schedule_prefix.typed_prefix_digest,
        target.schedule_prefix.artifact_prefix_digest,
        format_content_hash_ref(target.materialization.configuration),
        format_content_hash_ref(target.materialization.schedule),
        format_content_hash_ref(target.materialization.checkpoint),
        format_content_hash_ref(target.materialization.runtime_state),
        format_content_hash_ref(target.materialization.reduced_state),
        format_content_hash_ref(target.materialization.single_vm_fingerprint),
        format_content_hash_ref(target.materialization.graph),
        format_content_hash_ref(target.materialization.replay_fat_checkpoint),
        format_content_hash_ref(target.materialization.replay_thin_checkpoint),
        target.oracle.status_label(),
        target.oracle.store_objects
    )
}

pub(super) fn replay_bisect_machine_readable_summary(bisect: &ReplayBisectionReport) -> String {
    match &bisect.divergence {
        Some(divergence) => format!(
            "path={} status=diverged mismatch={} first_decision={} first_fingerprint_sample={} first_virtual_time={} first_virtual_time_node={} first_instruction={} first_instruction_node={} byte={} left_state={} right_state={}",
            bisect.other_path.display(),
            divergence.mismatch.label(),
            divergence
                .first_different_decision
                .map(|decision| decision.to_string())
                .unwrap_or_else(|| String::from("unknown")),
            divergence
                .first_different_fingerprint_sample
                .map(|sample| sample.to_string())
                .unwrap_or_else(|| String::from("unknown")),
            divergence
                .first_different_virtual_time
                .map(|ticks| ticks.to_string())
                .unwrap_or_else(|| String::from("unknown")),
            divergence
                .first_different_virtual_time_node
                .as_deref()
                .unwrap_or("unknown"),
            divergence
                .first_different_instruction
                .map(|instruction| instruction.to_string())
                .unwrap_or_else(|| String::from("unknown")),
            divergence
                .first_different_instruction_node
                .as_deref()
                .unwrap_or("unknown"),
            divergence.first_different_byte,
            divergence.left_state_digest,
            divergence.right_state_digest
        ),
        None => format!(
            "path={} status=byte-identical digest={}",
            bisect.other_path.display(),
            bisect.other_digest
        ),
    }
}
