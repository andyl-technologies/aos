//! Human-readable replay report rendering.

use super::*;

pub(crate) fn write_replay_report_human(
    output: &mut impl Write,
    report: &ReplayArtifactReport,
) -> io::Result<()> {
    writeln!(
        output,
        "crucible: replay artifact {} ({}) seed={} scenario={} digest={}",
        report.path.display(),
        REPRODUCTION_ARTIFACT_MEDIA_TYPE,
        report.seed,
        report.scenario_digest,
        report.digest
    )?;
    if let Some(reduction) = &report.reduction {
        writeln!(
            output,
            "crucible: replay reduction status=reexecuted artifact={} scenario={} schedule={} state={} reconstructed_decisions={}",
            format_content_hash_ref(reduction.artifact),
            format_content_hash_ref(reduction.scenario),
            format_content_hash_ref(reduction.schedule),
            format_content_hash_ref(reduction.state),
            reduction.reconstructed_decisions
        )?;
    }
    if let Some(live) = &report.live_qemu {
        writeln!(
            output,
            "crucible: replay live-qemu validation=passed producer={} reproduced_status={} reproduced_outcome={} terminal_configuration={} event_stream={} fingerprint_stream={} controls={}",
            live.producer,
            live.terminal_status,
            live.terminal_outcome,
            live.terminal_configuration,
            live.event_stream_digest,
            live.fingerprint_stream_digest,
            live.controls
        )?;
    }
    if let Some(check) = &report.check {
        match &check.mismatch {
            Some(mismatch) => {
                writeln!(
                    output,
                    "crucible: replay check {} status=mismatch expected={} replayed={} first_diff_byte={} original_len={} replayed_len={}",
                    check.path.display(),
                    mismatch.original_digest,
                    mismatch.replayed_digest,
                    mismatch.first_diff_byte,
                    mismatch.original_len,
                    mismatch.replayed_len
                )?;
            }
            None => {
                writeln!(
                    output,
                    "crucible: replay check {} status=byte-identical digest={}",
                    check.path.display(),
                    check.digest
                )?;
            }
        }
    }
    if let Some(target) = &report.to_savepoint {
        writeln!(output, "{}", replay_to_savepoint_status_line(target))?;
    }
    if let Some(bisect) = &report.bisect {
        match &bisect.divergence {
            Some(divergence) => {
                writeln!(
                    output,
                    "crucible: replay bisect {} status=diverged mismatch={} first_decision={} first_fingerprint_sample={} first_virtual_time={} first_virtual_time_node={} first_instruction={} first_instruction_node={} byte={} left_state={} right_state={}",
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
                )?;
            }
            None => {
                writeln!(
                    output,
                    "crucible: replay bisect {} status=byte-identical digest={}",
                    bisect.other_path.display(),
                    bisect.other_digest
                )?;
            }
        }
    }
    Ok(())
}
