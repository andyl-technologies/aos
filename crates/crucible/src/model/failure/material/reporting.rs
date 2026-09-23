//! Canonical minimization and cluster-report material.

use super::*;

pub(in crate::model) fn failure_signature_preserving_minimization_result_material(
    result: &FailureSignaturePreservingMinimizationResult,
) -> String {
    let mut lines = vec![
        result.policy.canonical_material(),
        format!("cluster_count={}", result.cluster_count()),
        format!("minimized_count={}", result.minimized_count()),
    ];
    for (run_index, run) in result.runs.iter().enumerate() {
        lines.push(format!("minimization.index={run_index}"));
        lines.push(format!(
            "minimization.cluster_id={}",
            content_hash_hex(run.cluster_id)
        ));
        lines.push(format!(
            "minimization.representative_artifact={}",
            content_hash_hex(run.representative_artifact)
        ));
        lines.push(format!(
            "minimization.disposition={}",
            match run.disposition {
                FailureMinimizationDisposition::Minimized => "minimized",
                FailureMinimizationDisposition::NotRequested => "not-requested",
                FailureMinimizationDisposition::NotApplicableTimeout => {
                    "not-applicable-timeout"
                }
            }
        ));
        lines.push(String::from("minimization.target_signature_key_BEGIN"));
        lines.push(run.target_signature_key.canonical_material().to_owned());
        lines.push(String::from("minimization.target_signature_key_END"));
        lines.push(String::from("minimization.minimized_signature_key_BEGIN"));
        lines.push(run.minimized_signature_key.canonical_material().to_owned());
        lines.push(String::from("minimization.minimized_signature_key_END"));
        lines.push(format!(
            "minimization.seed={}",
            run.minimization.seed.to_hex()
        ));
        match run.minimization.interesting_window {
            Some(window) => {
                lines.push(format!(
                    "minimization.interesting_window.original_schedule_len={}",
                    window.original_schedule_len()
                ));
                lines.push(format!(
                    "minimization.interesting_window.start={}",
                    window.start()
                ));
                lines.push(format!(
                    "minimization.interesting_window.end={}",
                    window.end()
                ));
                lines.push(format!(
                    "minimization.interesting_window.basis={}",
                    match window.basis() {
                        InterestingScheduleWindowBasis::LatestCampaignBranch => {
                            "latest-campaign-branch"
                        }
                        InterestingScheduleWindowBasis::TerminalSuffix => "terminal-suffix",
                    }
                ));
            }
            None => lines.push(String::from("minimization.interesting_window=none")),
        }
        lines.push(format!(
            "minimization.target_fingerprint={}",
            content_hash_hex(run.minimization.target_fingerprint)
        ));
        lines.push(format!(
            "minimization.original_artifact={}",
            content_hash_hex(run.minimization.original.artifact.id())
        ));
        lines.push(format!(
            "minimization.minimized_artifact={}",
            content_hash_hex(run.minimized_artifact())
        ));
        lines.push(format!(
            "minimization.attempt_count={}",
            run.minimization.attempts.len()
        ));
        lines.push(format!(
            "minimization.accepted_attempt_count={}",
            run.minimization.accepted_attempts()
        ));
        for (attempt_index, attempt) in run.minimization.attempts.iter().enumerate() {
            push_minimization_attempt_lines(run_index, attempt_index, attempt, &mut lines);
        }
        lines.push(format!(
            "minimization.signature_preserved={}",
            run.preserves_signature()
        ));
    }
    lines.join("\n")
}

pub(in crate::model) fn push_minimization_attempt_lines(
    run_index: usize,
    attempt_index: usize,
    attempt: &MinimizationAttempt,
    lines: &mut Vec<String>,
) {
    let prefix = format!("minimization.{run_index}.attempt.{attempt_index}");
    lines.push(format!("{prefix}.sequence={}", attempt.sequence));
    lines.push(format!(
        "{prefix}.removed_index_count={}",
        attempt.removed_indices.len()
    ));
    for (removed_index_index, removed_index) in attempt.removed_indices.iter().enumerate() {
        lines.push(format!(
            "{prefix}.removed_index.{removed_index_index}={removed_index}"
        ));
    }
    lines.push(format!(
        "{prefix}.removed_decision_count={}",
        attempt.removed_decisions.len()
    ));
    for (decision_index, decision) in attempt.removed_decisions.iter().enumerate() {
        let mut decision_lines = Vec::new();
        push_decision_lines(decision_index, decision, &mut decision_lines);
        for decision_line in decision_lines {
            lines.push(format!("{prefix}.removed_{decision_line}"));
        }
    }
    lines.push(format!(
        "{prefix}.candidate_artifact={}",
        content_hash_hex(attempt.candidate_artifact)
    ));
    lines.push(format!(
        "{prefix}.candidate_schedule={}",
        content_hash_hex(attempt.candidate_schedule)
    ));
    lines.push(format!(
        "{prefix}.replayed_state={}",
        content_hash_hex(attempt.replayed_state)
    ));
    match attempt.observed_fingerprint {
        Some(observed_fingerprint) => lines.push(format!(
            "{prefix}.observed_fingerprint={}",
            content_hash_hex(observed_fingerprint)
        )),
        None => lines.push(format!("{prefix}.observed_fingerprint=none")),
    }
    lines.push(format!("{prefix}.accepted={}", attempt.accepted));
}

pub(in crate::model) fn failure_report_anchor_index(
    finding: &FindingReproductionArtifact,
    failure: &FailureClusterReportFailure,
    event_log: &FailureRecordedEventLog,
    canonicalizer: &FailureSymmetryCanonicalizer,
) -> Result<usize, EngineError> {
    match failure {
        FailureClusterReportFailure::Property(record) => {
            if record.violation.reproduction_artifact != event_log.artifact() {
                return Err(EngineError::ReplayTargetMismatch {
                    expected: event_log.artifact(),
                    actual: record.violation.reproduction_artifact,
                });
            }
            validated_property_violation(finding, event_log, record, canonicalizer)?
                .anchor
                .ok_or(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-cluster-report",
                    reason: "host assertion has no retained causal anchor",
                })
        }
        FailureClusterReportFailure::Divergence(divergence) => {
            validate_divergence_point(event_log, &divergence.to_divergence_point())
        }
        FailureClusterReportFailure::Timeout(timeout) => validate_timeout_point(event_log, timeout),
    }
}

pub(in crate::model) fn failure_signature_for_report_failure(
    finding: &FindingReproductionArtifact,
    event_log: &FailureRecordedEventLog,
    failure: &FailureClusterReportFailure,
    normalization: &FailureSignatureNormalization,
) -> Result<FailureSignature, EngineError> {
    match failure {
        FailureClusterReportFailure::Property(record) => {
            FailureSignature::from_recorded_property_violation_with_normalization(
                finding,
                event_log,
                record,
                normalization,
            )
        }
        FailureClusterReportFailure::Divergence(divergence) => {
            FailureSignature::from_recorded_divergence_with_normalization(
                finding,
                event_log,
                &divergence.to_divergence_point(),
                normalization,
            )
        }
        FailureClusterReportFailure::Timeout(timeout) => {
            FailureSignature::from_recorded_timeout_with_normalization(
                finding,
                event_log,
                timeout,
                normalization,
            )
        }
    }
}

pub(in crate::model) fn failure_report_excerpt(
    event_log: &FailureRecordedEventLog,
    causal_index: usize,
    excerpt_len: usize,
    canonicalizer: &FailureSymmetryCanonicalizer,
) -> Vec<FailureClusterReportCausalStep> {
    if excerpt_len == 0 {
        return Vec::new();
    }
    let start = causal_index.saturating_add(1).saturating_sub(excerpt_len);
    event_log.projection.entries()[start..=causal_index]
        .iter()
        .map(|entry| failure_cluster_report_causal_step(entry, canonicalizer))
        .collect()
}

pub(in crate::model) fn failure_cluster_report_causal_step(
    entry: &crate::scheduler::EventLogCausalProjectionEntry,
    canonicalizer: &FailureSymmetryCanonicalizer,
) -> FailureClusterReportCausalStep {
    let node = entry
        .entry
        .time()
        .icount
        .node
        .as_ref()
        .map(|node| canonicalizer.canonical_node(node))
        .or_else(|| match entry.entry.source() {
            EventSource::Node { node } | EventSource::Guest { node } => {
                Some(canonicalizer.canonical_node(node))
            }
            EventSource::Scenario { .. } | EventSource::Engine | EventSource::Command { .. } => {
                None
            }
        });
    let source = failure_event_source_material("source", entry.entry.source(), canonicalizer)
        .strip_prefix("source=")
        .unwrap_or("unknown")
        .to_owned();
    FailureClusterReportCausalStep {
        raw_index: entry.raw_index,
        sequence: entry.entry.sequence(),
        node,
        icount: entry.entry.time().icount.icount,
        kind: entry.entry.event_payload().kind().to_owned(),
        source,
        entry: entry.entry.content_hash(),
    }
}

pub(in crate::model) fn failure_cluster_report_material(report: &FailureClusterReport) -> String {
    let mut lines = vec![
        report.policy.canonical_material(),
        format!("cluster_id={}", content_hash_hex(report.cluster_id)),
        String::from("signature_BEGIN"),
        report.signature.report_material(),
        String::from("signature_END"),
        format!("member_count={}", report.member_count),
    ];
    for (index, member) in report.member_hashes.iter().enumerate() {
        lines.push(format!(
            "member.{index}.reproduction_artifact={}",
            content_hash_hex(*member)
        ));
    }
    lines.push(format!(
        "representative_artifact={}",
        content_hash_hex(report.representative_artifact)
    ));
    lines.push(format!(
        "minimal_representative={}",
        content_hash_hex(report.minimal_representative)
    ));
    push_failure_report_reproduction_lines(
        "minimal_reproduction",
        &report.minimal_reproduction,
        &mut lines,
    );
    push_failure_report_failure_lines("failure", &report.failure, &mut lines);
    lines.push(format!(
        "event_log_excerpt_count={}",
        report.event_log_excerpt.len()
    ));
    for (index, step) in report.event_log_excerpt.iter().enumerate() {
        push_failure_report_step_lines(&format!("event_log_excerpt.{index}"), step, &mut lines);
    }
    lines.push(format!("causal_chain_count={}", report.causal_chain.len()));
    for (index, step) in report.causal_chain.iter().enumerate() {
        push_failure_report_step_lines(&format!("causal_chain.{index}"), step, &mut lines);
    }
    lines.push(format!(
        "replay_command_len={}",
        report.replay_command.len()
    ));
    lines.push(format!("replay_command={}", report.replay_command));
    lines.join("\n")
}

pub(in crate::model) fn push_failure_report_reproduction_lines(
    prefix: &str,
    reproduction: &FailureClusterReportReproduction,
    lines: &mut Vec<String>,
) {
    lines.push(format!(
        "{prefix}.artifact={}",
        content_hash_hex(reproduction.artifact)
    ));
    lines.push(format!("{prefix}.seed={}", reproduction.seed.to_hex()));
    lines.push(format!(
        "{prefix}.scenario={}",
        content_hash_hex(reproduction.scenario)
    ));
    lines.push(format!(
        "{prefix}.schedule={}",
        content_hash_hex(reproduction.schedule)
    ));
}

pub(in crate::model) fn push_failure_report_failure_lines(
    prefix: &str,
    failure: &FailureClusterReportFailure,
    lines: &mut Vec<String>,
) {
    match failure {
        FailureClusterReportFailure::Property(record) => {
            lines.push(format!("{prefix}.kind=property-violation"));
            lines.push(assertion_id_material(&record.violation.assertion));
            lines.push(format!(
                "{prefix}.property_message_len={}",
                record.violation.message.len()
            ));
            lines.push(format!(
                "{prefix}.property_message={}",
                record.violation.message
            ));
            lines.push(format!(
                "{prefix}.property_quantifier={}",
                failure_assertion_quantifier_label(record.violation.quantifier)
            ));
            lines.push(format!(
                "{prefix}.event_kind_len={}",
                record.violation.event_kind.len()
            ));
            lines.push(format!(
                "{prefix}.event_kind={}",
                record.violation.event_kind
            ));
            lines.push(
                record
                    .violation
                    .at_icount
                    .map(|icount| format!("{prefix}.at_icount={}", icount.retired))
                    .unwrap_or_else(|| format!("{prefix}.at_icount=none")),
            );
            match &record.violation.node {
                Some(node) => lines.push(node_ref_material(&format!("{prefix}.node"), node)),
                None => lines.push(format!("{prefix}.node=none")),
            }
            lines.push(format!(
                "{prefix}.detail_len={}",
                record.violation.detail.len()
            ));
            lines.push(format!("{prefix}.detail={}", record.violation.detail));
            lines.push(format!(
                "{prefix}.reproduction_artifact={}",
                content_hash_hex(record.violation.reproduction_artifact)
            ));
        }
        FailureClusterReportFailure::Divergence(divergence) => {
            lines.push(format!("{prefix}.kind=divergence"));
            lines.push(format!("{prefix}.raw_index={}", divergence.raw_index));
            match &divergence.node {
                Some(node) => lines.push(node_ref_material(&format!("{prefix}.node"), node)),
                None => lines.push(format!("{prefix}.node=none")),
            }
            match &divergence.icount_node {
                Some(node) => lines.push(node_ref_material(&format!("{prefix}.icount_node"), node)),
                None => lines.push(format!("{prefix}.icount_node=none")),
            }
            lines.push(format!("{prefix}.icount={}", divergence.icount.retired));
            lines.push(failure_event_source_material(
                &format!("{prefix}.source"),
                &divergence.source,
                &FailureSymmetryCanonicalizer::identity(ContentHash::default()),
            ));
            lines.push(format!("{prefix}.kind_len={}", divergence.kind.len()));
            lines.push(format!("{prefix}.event_kind={}", divergence.kind));
            lines.push(format!(
                "{prefix}.expected_state_summary_len={}",
                divergence.expected_state_summary.len()
            ));
            lines.push(format!(
                "{prefix}.expected_state_summary={}",
                divergence.expected_state_summary
            ));
            lines.push(format!(
                "{prefix}.reproduced_state_summary_len={}",
                divergence.reproduced_state_summary.len()
            ));
            lines.push(format!(
                "{prefix}.reproduced_state_summary={}",
                divergence.reproduced_state_summary
            ));
        }
        FailureClusterReportFailure::Timeout(timeout) => {
            lines.push(format!("{prefix}.kind=timeout"));
            lines.push(format!(
                "{prefix}.budget_kind={}",
                failure_timeout_budget_kind_label(timeout.budget_kind)
            ));
            lines.push(
                timeout
                    .configured_limit
                    .map(|limit| format!("{prefix}.configured_limit={limit}"))
                    .unwrap_or_else(|| format!("{prefix}.configured_limit=none")),
            );
            lines.push(format!(
                "{prefix}.observed_quanta={}",
                timeout.observed_quanta
            ));
            lines.push(format!(
                "{prefix}.at_virtual_time={}",
                timeout.at_virtual_time.ticks
            ));
            lines.push(
                timeout
                    .at_icount
                    .map(|icount| format!("{prefix}.at_icount={}", icount.retired))
                    .unwrap_or_else(|| format!("{prefix}.at_icount=none")),
            );
            match &timeout.node {
                Some(node) => lines.push(node_ref_material(&format!("{prefix}.node"), node)),
                None => lines.push(format!("{prefix}.node=none")),
            }
            lines.push(format!("{prefix}.event_kind={}", timeout.event_kind));
            lines.push(format!(
                "{prefix}.reproduction_artifact={}",
                content_hash_hex(timeout.reproduction_artifact)
            ));
        }
    }
}

pub(in crate::model) fn push_failure_report_step_lines(
    prefix: &str,
    step: &FailureClusterReportCausalStep,
    lines: &mut Vec<String>,
) {
    lines.push(format!("{prefix}.raw_index={}", step.raw_index));
    lines.push(format!("{prefix}.sequence={}", step.sequence));
    match &step.node {
        Some(node) => lines.push(node_ref_material(&format!("{prefix}.node"), node)),
        None => lines.push(format!("{prefix}.node=none")),
    }
    lines.push(format!("{prefix}.icount={}", step.icount.retired));
    lines.push(format!("{prefix}.kind_len={}", step.kind.len()));
    lines.push(format!("{prefix}.kind={}", step.kind));
    lines.push(format!("{prefix}.source_len={}", step.source.len()));
    lines.push(format!("{prefix}.source={}", step.source));
    lines.push(format!("{prefix}.entry={}", content_hash_hex(step.entry)));
}

pub(in crate::model) fn failure_cluster_report_set_material(
    report_set: &FailureClusterReportSet,
) -> String {
    let mut lines = vec![
        report_set.policy.canonical_material(),
        format!("report_count={}", report_set.reports.len()),
    ];
    for (index, report) in report_set.reports.iter().enumerate() {
        lines.push(format!("report.index={index}"));
        lines.push(format!(
            "report.cluster_id={}",
            content_hash_hex(report.cluster_id)
        ));
        lines.push(format!(
            "report.content_hash={}",
            content_hash_hex(report.content_hash())
        ));
    }
    lines.join("\n")
}

pub(in crate::model) fn failure_cluster_report_json(report: &FailureClusterReport) -> String {
    let members = report
        .member_hashes
        .iter()
        .map(|hash| json_string(&format_content_hash_ref(*hash)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"schema\":{},\"cluster_id\":{},\"policy\":{},\"report_hash\":{},\"signature_hash\":{},\"member_count\":{},\"member_hashes\":[{}],\"minimal_representative\":{},\"replay_command\":{},\"canonical_material\":{}}}",
        json_string(FAILURE_CLUSTER_REPORT_DOMAIN),
        json_string(&format_content_hash_ref(report.cluster_id)),
        json_string(signature_policy_level_label(report.policy.level())),
        json_string(&format_content_hash_ref(report.content_hash())),
        json_string(&format_content_hash_ref(report.signature.content_hash())),
        report.member_count,
        members,
        json_string(&format_content_hash_ref(report.minimal_representative)),
        json_string(&report.replay_command),
        json_string(&report.canonical_material()),
    )
}

pub(in crate::model) fn failure_cluster_report_set_json(
    report_set: &FailureClusterReportSet,
) -> String {
    let reports = report_set
        .reports
        .iter()
        .map(failure_cluster_report_json)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"schema\":{},\"policy\":{},\"report_set_hash\":{},\"report_count\":{},\"reports\":[{}],\"canonical_material\":{}}}",
        json_string(FAILURE_CLUSTER_REPORT_SET_DOMAIN),
        json_string(signature_policy_level_label(report_set.policy.level())),
        json_string(&format_content_hash_ref(report_set.content_hash())),
        report_set.reports.len(),
        reports,
        json_string(&report_set.canonical_material()),
    )
}

pub(in crate::model) fn failure_cluster_report_table(report: &FailureClusterReport) -> String {
    let mut lines = vec![
        String::from("field\tvalue"),
        format!("cluster_id\t{}", format_content_hash_ref(report.cluster_id)),
        format!(
            "minimal_representative\t{}",
            format_content_hash_ref(report.minimal_representative)
        ),
        format!("member_count\t{}", report.member_count),
        format!("replay_command\t{}", report.replay_command),
    ];
    for line in report.canonical_material().lines() {
        let (field, value) = line.split_once('=').unwrap_or((line, ""));
        lines.push(format!("canonical.{field}\t{value}"));
    }
    lines.join("\n")
}

pub(in crate::model) fn failure_cluster_report_markdown(report: &FailureClusterReport) -> String {
    format!(
        "# Crucible Triage Cluster {}\n\n- Policy: {}\n- Members: {}\n- Minimal representative: {}\n- Replay: `{}`\n\n## Canonical Report\n\n```text\n{}\n```",
        format_content_hash_ref(report.cluster_id),
        signature_policy_level_label(report.policy.level()),
        report.member_count,
        format_content_hash_ref(report.minimal_representative),
        report.replay_command,
        report.canonical_material(),
    )
}

pub(in crate::model) fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0c}' => escaped.push_str("\\f"),
            ch if ch.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", u32::from(ch)));
            }
            ch => escaped.push(ch),
        }
    }
    escaped.push('"');
    escaped
}
