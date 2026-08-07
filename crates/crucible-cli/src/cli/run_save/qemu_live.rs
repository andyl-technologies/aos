//! Live local backend execution through the packaged patched emulator and plugin.

use super::*;

/// Maximum scheduler quanta for one live exploration realization.
///
/// Exact local events and conservative link horizons may split a realization;
/// the bound leaves room for both VM nodes and terminal scheduler settling.
pub(crate) const LIVE_EXPLORATION_QUANTUM_LIMIT: u64 = 16;

/// Terminal instruction-count ceiling for one live exploration realization.
///
/// The certified stock-kernel network workload emits near 3.3 billion
/// instructions and resolves its link delivery below this three-window bound.
pub(crate) const LIVE_EXPLORATION_RUN_CEILING_ICOUNT: u64 = 12_000_000_000;

/// Terminal instruction-count ceiling for a production CLI lifecycle session.
pub(crate) const PRODUCTION_CLI_RUN_CEILING_ICOUNT: u64 = 40_000_000_000;

/// Scheduler-quantum ceiling for a production CLI lifecycle session.
pub(crate) const PRODUCTION_CLI_QUANTUM_BUDGET: u64 = 10_000;

/// Per-node wall-clock timeout for a production CLI lifecycle step.
const PRODUCTION_CLI_COMPLETION_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug)]
pub(crate) struct SelftestGateReport {
    pub(crate) name: String,
    pub(crate) status: SelftestGateStatus,
    pub(crate) corpus_entries: usize,
    pub(crate) runs_per_entry: usize,
    pub(crate) runner: SelftestGateRunner,
    pub(crate) qemu_build_id: Option<String>,
    pub(crate) live_qemu_icount: Option<u64>,
    pub(crate) live_qemu_fingerprint: Option<String>,
}

#[path = "qemu_live/probe.rs"]
mod probe;

pub(crate) use probe::*;

pub(crate) fn is_packaged_backend(backend_plan: &BackendSelectionPlan) -> bool {
    matches!(
        backend_plan.resolved_backend,
        Some(ResolvedLocalBackend::Qemu { .. })
    )
}

pub(crate) fn run_selftest(cli: &Cli, args: &SelftestArgs) -> Result<SelftestReport, CliError> {
    run_selftest_with_probe(cli, args, &mut ProductionLiveQemuProbeRunner)
}

pub(crate) fn run_selftest_with_probe(
    cli: &Cli,
    args: &SelftestArgs,
    probe: &mut impl LiveQemuProbeRunner,
) -> Result<SelftestReport, CliError> {
    let selected_gates = plan_selftest_gates(args)?;
    let qemu_backend = if selected_gates
        .iter()
        .any(|gate| selftest_gate_uses_real_backend(gate))
    {
        Some(require_selftest_qemu_backend(cli)?)
    } else {
        None
    };
    #[cfg(any(test, feature = "test-double"))]
    let verified = verify_selftest_corpus(args)?;
    #[cfg(not(any(test, feature = "test-double")))]
    let verified = Vec::new();
    let mut gates = Vec::with_capacity(selected_gates.len());
    let mut live_baseline = None;
    for gate in selected_gates {
        let runner = if selftest_gate_uses_real_backend(&gate) {
            SelftestGateRunner::RealQemu
        } else {
            #[cfg(any(test, feature = "test-double"))]
            {
                SelftestGateRunner::DoubleBackedCorpus
            }
            #[cfg(not(any(test, feature = "test-double")))]
            {
                return Err(backend_error(format!(
                    "selftest gate `{gate}` requires the `test-double` Cargo feature"
                )));
            }
        };
        let live = if runner == SelftestGateRunner::RealQemu {
            let backend = qemu_backend
                .as_ref()
                .ok_or_else(|| backend_error("real-QEMU selftest requires a resolved backend"))?;
            let evidence = probe.run_probe(backend)?;
            validate_live_qemu_probe_evidence(backend, &evidence)?;
            if live_baseline
                .as_ref()
                .is_some_and(|baseline| baseline != &evidence)
            {
                return Err(backend_error(
                    "live QEMU selftest probes diverged across identical executions",
                ));
            }
            live_baseline.get_or_insert_with(|| evidence.clone());
            Some(evidence)
        } else {
            None
        };
        gates.push(SelftestGateReport {
            name: gate,
            status: SelftestGateStatus::Passed,
            corpus_entries: verified.len(),
            runs_per_entry: DEFAULT_SELFTEST_RUNS,
            runner,
            qemu_build_id: live.as_ref().map(|evidence| evidence.qemu_build_id.clone()),
            live_qemu_icount: live.as_ref().map(|report| report.completed_icount),
            live_qemu_fingerprint: live
                .as_ref()
                .map(|report| report.execution_fingerprint.clone()),
        });
    }
    Ok(SelftestReport { gates, verified })
}

fn validate_live_qemu_probe_evidence(
    backend: &ResolvedLocalBackend,
    evidence: &LiveQemuProbeEvidence,
) -> Result<(), CliError> {
    let observed = BackendExecutionEvidence::LocalProduction {
        build_id: evidence.qemu_build_id.clone(),
        plugin_abi: evidence.plugin_abi.clone(),
    };
    let plan = BackendSelectionPlan {
        subcommand: CliSubcommand::Selftest,
        target: BackendExecutionTarget::Local,
        requested_backend: Backend::Qemu,
        resolved_backend: Some(backend.clone()),
        reason: BackendSelectionReason::ExplicitQemu,
        daemon: None,
        daemon_security: None,
        remote_uses_control_api: false,
        local_uses_simulation_backend: true,
        local_remote_equivalence_contract: true,
    };
    let expected = plan
        .expected_execution_evidence()
        .ok_or_else(|| backend_error("live QEMU probe has no selected execution identity"))?;
    if expected != observed || !observed.proves_t_cli_3(&plan) {
        return Err(backend_error(
            "live QEMU probe identity does not match the discovered backend",
        ));
    }
    Ok(())
}

#[cfg(not(test))]
pub(crate) fn require_selftest_qemu_backend(cli: &Cli) -> Result<ResolvedLocalBackend, CliError> {
    require_qemu_artifacts(
        cli,
        &ProcessQemuDiscoveryEnvironment,
        &CompileTimeAosQemuPackageSet,
    )
}

#[cfg(test)]
pub(crate) fn require_selftest_qemu_backend(cli: &Cli) -> Result<ResolvedLocalBackend, CliError> {
    require_qemu_artifacts(cli, &ProcessQemuDiscoveryEnvironment, &NoAosQemuPackageSet)
}

pub(crate) fn run_local_qemu_fuzz_workflow(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    plan: &FuzzDriverPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let backend = backend_plan
        .resolved_backend
        .as_ref()
        .ok_or_else(|| backend_error("local QEMU fuzz requires a resolved backend"))?;
    let family = load_fuzz_family(plan)?;
    let config = production_qemu_lifecycle_config(backend)?
        .with_coverage(production_api::ProductionPluginSwitch::On);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let warmup = family
        .fuzz_coverage_guided(plan.config, &[])
        .map_err(|error| backend_error(format!("QEMU fuzz warm-up policy failed: {error}")))?;
    let mut execution =
        execute_qemu_fuzz_iterations(&config, &runtime, &warmup, "warm-up", plan, backend_plan)?;
    let (run, mut report) = if let Some(corpus) = &plan.corpus {
        fs::create_dir_all(corpus).map_err(|error| {
            backend_error(format!(
                "QEMU fuzz could not create corpus `{}`: {error}",
                corpus.display()
            ))
        })?;
        let store = crucible::LocalDagStore::new(corpus.clone());
        let corpus_run = family
            .fuzz_coverage_guided_corpus(
                &store,
                plan.config,
                crucible::CoverageGuidedCorpusConfig::new(plan.config.meta_seed),
                &execution.feedback,
            )
            .map_err(|error| backend_error(format!("QEMU fuzz corpus policy failed: {error}")))?;
        (
            corpus_run.fuzz.clone(),
            local_double_fuzz_report_from_corpus_run(plan, corpus, &corpus_run),
        )
    } else {
        let run = family
            .fuzz_coverage_guided(plan.config, &execution.feedback)
            .map_err(|error| backend_error(format!("QEMU fuzz policy failed: {error}")))?;
        let report = local_double_fuzz_report_from_run(plan, &run);
        (run, report)
    };
    let guided_execution =
        if plan.on_violation == SearchOnViolationArg::Stop && !execution.findings.is_empty() {
            QemuFuzzExecution::default()
        } else {
            execute_qemu_fuzz_iterations(&config, &runtime, &run, "guided", plan, backend_plan)?
        };
    merge_qemu_fuzz_execution(&mut execution, guided_execution)?;
    report.property_findings = execution
        .findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.failure,
                crucible_model::FailureClusterReportFailure::Property(_)
            )
        })
        .count();
    report.timeout_findings = execution
        .findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.failure,
                crucible_model::FailureClusterReportFailure::Timeout(_)
            )
        })
        .count();
    let mut outcome = backend_command_outcome(thin_plan, backend_plan, ergonomics_plan);
    apply_local_double_fuzz_report(&mut outcome, plan, &report);
    for (index, feedback) in execution.feedback.iter().enumerate() {
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: String::from("qemu"),
            kind: String::from("fuzz_coverage_feedback"),
            summary: format!(
                "iteration={index}\tblocks={}\tfingerprint={}",
                feedback.projection().len(),
                feedback.fingerprint().to_hex()
            ),
        });
    }
    attach_qemu_findings_outputs(
        &mut outcome,
        &plan.store_root,
        &plan.artifact_dir,
        plan.findings_out.as_deref(),
        execution.findings,
        execution.reproduction_artifacts,
    )?;
    append_qemu_control_plane_execution_proof(&mut outcome, backend, "fuzz-live-campaign");
    Ok(outcome)
}

#[derive(Default)]
struct QemuFuzzExecution {
    feedback: Vec<crucible::EventLogCoverageFeedback>,
    findings: Vec<TriageFindingEvidence>,
    reproduction_artifacts: Vec<Vec<u8>>,
}

fn execute_qemu_fuzz_iterations(
    config: &production_api::ProductionVmLifecycleConfig,
    runtime: &tokio::runtime::Runtime,
    run: &crucible::CoverageGuidedFuzzRun,
    phase: &str,
    plan: &FuzzDriverPlan,
    backend_plan: &BackendSelectionPlan,
) -> Result<QemuFuzzExecution, CliError> {
    let mut execution = QemuFuzzExecution {
        feedback: Vec::with_capacity(run.iterations.len()),
        ..QemuFuzzExecution::default()
    };
    for iteration in &run.iterations {
        let form = iteration.scenario.form().clone();
        let run_plan = qemu_fuzz_iteration_plan(iteration.sequence, form.clone());
        // crucible-lint: allow host-nondeterminism-state -- genesis is reconstructed from canonical scenario material, not host observations.
        let branch_base = crucible::Configuration::genesis(iteration.scenario.scenario_def());
        let iteration_config = config.clone().with_branch_prefix_overrides(
            branch_base,
            VirtualTime { ticks: 0 },
            iteration.schedule().decisions().to_vec(),
        );
        let control_plane =
            production_qemu_control_plane(iteration_config, run_plan.scenario.scenario_form());
        let client = InProcessLifecycleClient::new(control_plane);
        let report =
            runtime.block_on(run_control_client_workflow_async(&client, &run_plan, &[]))?;
        if report.status == BackendCommandStatus::Crashed {
            return Err(backend_error(format!(
                "QEMU fuzz {phase} iteration {} crashed before producing campaign evidence",
                iteration.sequence,
            )));
        }
        if report.status == BackendCommandStatus::Passed
            && report.coverage_feedback.projection().is_empty()
        {
            return Err(backend_error(format!(
                "QEMU fuzz {phase} iteration {} produced no basic-block coverage",
                iteration.sequence,
            )));
        }
        let recorded_overrides = report
            .streamed_event_frames
            .iter()
            .filter(|frame| String::from_utf8_lossy(frame).contains("kind=crucible.event.override"))
            .count();
        let expected_overrides = iteration
            .schedule()
            .decisions()
            .iter()
            // crucible-lint: allow host-nondeterminism-state -- counting recorded canonical choices does not alter their values or order.
            .filter(|decision| matches!(decision, crucible::Decision::Override(_)))
            .count();
        if recorded_overrides != expected_overrides {
            return Err(backend_error(format!(
                "QEMU fuzz {phase} iteration {} recorded {recorded_overrides} override events, expected {expected_overrides}",
                iteration.sequence,
            )));
        }
        let finding = qemu_fuzz_finding_evidence(
            &form,
            &report,
            phase,
            iteration.sequence,
            iteration.schedule().len(),
            backend_plan,
        )?;
        execution.feedback.push(report.coverage_feedback);
        if let Some((evidence, reproduction)) = finding {
            let store = crucible::LocalDagStore::new(plan.store_root.clone());
            let stored = evidence
                .finding
                .store_artifact(&store)
                .map_err(CliError::Store)?;
            if stored != evidence.finding.artifact.id() {
                return Err(artifact_error(
                    "stored fuzz finding artifact did not match its content identity",
                ));
            }
            push_qemu_fuzz_finding(&mut execution, evidence, reproduction)?;
            if plan.on_violation == SearchOnViolationArg::Stop {
                break;
            }
        }
    }
    Ok(execution)
}

fn qemu_fuzz_finding_evidence(
    form: &crucible::ScenarioDefForm,
    report: &RunWorkflowReport,
    phase: &str,
    sequence: u64,
    branch_decisions: usize,
    backend_plan: &BackendSelectionPlan,
) -> Result<Option<(crate::cli_report::TriageFindingEvidence, Vec<u8>)>, CliError> {
    if report.status == BackendCommandStatus::Passed {
        return Ok(None);
    }
    let terminal = report.terminal_configuration.as_ref().ok_or_else(|| {
        backend_error(format!(
            "QEMU fuzz {phase} iteration {sequence} did not retain a terminal configuration"
        ))
    })?;
    let finding_fingerprint = crucible::ContentHash::from_canonical_material(
        "crucible.live-qemu-fuzz-finding.v2",
        &format!(
            "configuration={}\noutcome={}",
            terminal.id().to_hex(),
            report.status.label()
        ),
    );
    let finding = crucible::FindingReproductionArtifact::capture(
        crucible::FindingDiscoveryPath::CoverageGuidedFuzzing,
        finding_fingerprint,
        form,
        terminal,
    )
    .map_err(|error| backend_error(format!("capture QEMU fuzz finding: {error}")))?;
    let evidence = match report.status {
        BackendCommandStatus::Failed => {
            let violation = qemu_property_violation_from_frames(
                form,
                &report.streamed_event_frames,
                finding.artifact.id(),
            )?;
            crate::cli_triage_debug::triage_property_evidence_for_violation_with_recording(
                finding,
                violation,
                report.coverage_feedback.fingerprint(),
                report.streamed_event_frames.clone(),
            )
        }
        BackendCommandStatus::Timeout => {
            let timeout = crucible_model::FailureTimeoutRecord::new(
                crucible_model::FailureTimeoutBudgetKind::ExecutionQuanta,
                None,
                report.final_quanta,
                crucible::VirtualTime {
                    ticks: report.final_frontier_ticks,
                },
                None,
                None,
                finding.artifact.id(),
            );
            crate::cli_triage_debug::triage_timeout_evidence(
                finding,
                timeout,
                report.coverage_feedback.fingerprint(),
                report.streamed_event_frames.clone(),
            )
        }
        BackendCommandStatus::Crashed => {
            return Err(backend_error(format!(
                "QEMU fuzz {phase} iteration {sequence} crashed before producing campaign evidence"
            )));
        }
        BackendCommandStatus::Passed => return Ok(None),
    }
    .map_err(|error| backend_error(format!("build QEMU fuzz finding evidence: {error}")))?;
    let reproduction = live_finding_reproduction_artifact_bytes(
        backend_plan.resolved_backend.as_ref(),
        &evidence.finding,
        "fuzz",
        &qemu_fuzz_iteration_plan(sequence, form.clone()),
        report,
        LiveQemuReplayBranch::PrefixOverrides {
            base_decisions: 0,
            frontier_ticks: 0,
            decision_start: 0,
            decision_end: branch_decisions as u64,
        },
    )?;
    Ok(Some((evidence, reproduction)))
}

fn push_qemu_fuzz_finding(
    execution: &mut QemuFuzzExecution,
    evidence: TriageFindingEvidence,
    reproduction: Vec<u8>,
) -> Result<(), CliError> {
    let artifact = evidence.finding.artifact.id();
    if let Some(index) = execution
        .findings
        .iter()
        .position(|existing| existing.finding.artifact.id() == artifact)
    {
        if execution.findings[index] != evidence
            || execution.reproduction_artifacts.get(index) != Some(&reproduction)
        {
            return Err(artifact_error(
                "repeated fuzz reproduction produced conflicting deterministic evidence",
            ));
        }
        return Ok(());
    }
    execution.findings.push(evidence);
    execution.reproduction_artifacts.push(reproduction);
    Ok(())
}

fn merge_qemu_fuzz_execution(
    target: &mut QemuFuzzExecution,
    source: QemuFuzzExecution,
) -> Result<(), CliError> {
    if source.findings.len() != source.reproduction_artifacts.len() {
        return Err(artifact_error(
            "fuzz phase produced mismatched finding and reproduction counts",
        ));
    }
    target.feedback.extend(source.feedback);
    for (evidence, reproduction) in source
        .findings
        .into_iter()
        .zip(source.reproduction_artifacts)
    {
        push_qemu_fuzz_finding(target, evidence, reproduction)?;
    }
    Ok(())
}

fn qemu_property_violation_from_frames(
    form: &crucible::ScenarioDefForm,
    frames: &[Vec<u8>],
    reproduction_artifact: crucible::ContentHash,
) -> Result<crucible_model::HostAssertionViolation, CliError> {
    let mut violations = Vec::new();
    for frame in frames {
        let text = std::str::from_utf8(frame)
            .map_err(|error| backend_error(format!("QEMU event frame is not UTF-8: {error}")))?;
        if canonical_frame_value(text, "kind") != Some("crucible.event.assertion_state_changed") {
            continue;
        }
        let Some(assertion_name) = canonical_frame_string_attribute(text, "id")? else {
            continue;
        };
        if canonical_frame_string_attribute(text, "new_state")?.as_deref() != Some("Violated") {
            continue;
        }
        let assertion = form
            .properties()
            .assertions()
            .iter()
            .find(|candidate| candidate.id.name == assertion_name)
            .ok_or_else(|| {
                backend_error(format!(
                    "QEMU violation referenced undeclared assertion `{assertion_name}`"
                ))
            })?;
        let at_virtual_time = canonical_frame_u64(text, "virtual-time-ticks")?;
        let at_icount = canonical_frame_u64(text, "icount-retired")?;
        let node = match canonical_frame_value(text, "icount-node") {
            Some("none") | None => None,
            Some(value) => Some(crucible::NodeId {
                name: canonical_frame_hex_string("icount-node", value)?,
            }),
        };
        violations.push(crucible_model::HostAssertionViolation {
            assertion: assertion.id.clone(),
            message: assertion.message.clone(),
            quantifier: assertion.quantifier_kind(),
            event_kind: String::from("assertion_state_changed"),
            at_icount: Some(crucible::Icount { retired: at_icount }),
            at_virtual_time: crucible::VirtualTime {
                ticks: at_virtual_time,
            },
            node,
            detail: String::from("assertion entered the Violated state"),
            reproduction_artifact,
        });
    }
    violations.sort_by(|left, right| {
        (
            left.assertion.name.as_str(),
            left.at_virtual_time.ticks,
            left.at_icount.map(|value| value.retired),
            left.node.as_ref().map(|node| node.name.as_str()),
        )
            .cmp(&(
                right.assertion.name.as_str(),
                right.at_virtual_time.ticks,
                right.at_icount.map(|value| value.retired),
                right.node.as_ref().map(|node| node.name.as_str()),
            ))
    });
    violations.into_iter().next().ok_or_else(|| {
        backend_error("failed QEMU iteration did not stream an assertion violation event")
    })
}

fn canonical_frame_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        line.strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
    })
}

fn canonical_frame_u64(text: &str, key: &'static str) -> Result<u64, CliError> {
    canonical_frame_value(text, key)
        .ok_or_else(|| backend_error(format!("QEMU event frame is missing `{key}`")))?
        .parse::<u64>()
        .map_err(|_| backend_error(format!("QEMU event frame has invalid `{key}`")))
}

fn canonical_frame_string_attribute(
    text: &str,
    requested_name: &str,
) -> Result<Option<String>, CliError> {
    for line in text
        .lines()
        .filter_map(|line| line.strip_prefix("attribute="))
    {
        let mut fields = line.split('|');
        let Some(name_hex) = fields.next() else {
            continue;
        };
        let Some(kind) = fields.next() else {
            continue;
        };
        let Some(value_hex) = fields.next() else {
            continue;
        };
        if canonical_frame_hex_string("attribute-name", name_hex)? == requested_name {
            if kind != "string" {
                return Err(backend_error(format!(
                    "QEMU event attribute `{requested_name}` is not a string"
                )));
            }
            return canonical_frame_hex_string(requested_name, value_hex).map(Some);
        }
    }
    Ok(None)
}

fn canonical_frame_hex_string(field: &str, value: &str) -> Result<String, CliError> {
    let bytes = parse_hex_bytes(0, field, value)?;
    String::from_utf8(bytes)
        .map_err(|error| backend_error(format!("QEMU event `{field}` is not UTF-8: {error}")))
}

fn attach_qemu_findings_outputs(
    outcome: &mut BackendCommandOutcome,
    store_root: &Path,
    artifact_dir: &Path,
    findings_out: Option<&Path>,
    findings: Vec<crate::cli_report::TriageFindingEvidence>,
    reproduction_artifacts: Vec<Vec<u8>>,
) -> Result<(), CliError> {
    if findings.is_empty() {
        return Ok(());
    }
    let (path, digest, ledger_bytes) = crate::cli_triage_debug::write_failure_findings_ledger_v3(
        artifact_dir,
        findings_out,
        &findings,
    )?;
    let store = crucible::LocalDagStore::new(store_root.to_path_buf());
    let stored = store.put(&ledger_bytes).map_err(CliError::Store)?;
    if stored != digest {
        return Err(artifact_error(
            "stored findings ledger did not match its content identity",
        ));
    }
    outcome.stdout.push(format!(
        "findings-ledger\tpath={}\tdigest={}\tfindings={}",
        path.display(),
        format_content_hash_ref(digest),
        findings.len()
    ));
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("crucible"),
        kind: String::from("signed_findings_ledger"),
        summary: format!(
            "digest={} findings={}",
            format_content_hash_ref(digest),
            findings.len()
        ),
    });
    match reproduction_artifacts.as_slice() {
        [artifact] => outcome.reproduction_artifact = Some(artifact.clone()),
        artifacts => {
            outcome.side_reproduction_artifacts = artifacts
                .iter()
                .enumerate()
                .map(|(index, artifact)| (format!("finding-{index}"), artifact.clone()))
                .collect();
        }
    }
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
    Ok(())
}

#[cfg(test)]
mod finding_tests {
    use super::*;

    #[test]
    fn live_qemu_property_evidence_reads_exact_stream_frame()
    -> Result<(), Box<dyn std::error::Error>> {
        use crucible_api::OpenSetAttributeValue::String as Text;

        let scenario = crucible::happy_path_scenario()?.scenario;
        let assertion = scenario
            .properties()
            .assertions()
            .first()
            .ok_or_else(|| std::io::Error::other("fixture has no assertion"))?;
        let frame = crucible_api::StreamingEventFrame {
            generation: 0,
            cursor: crucible_api::EventLogCursor::new(4),
            next_cursor: crucible_api::EventLogCursor::new(5),
            event: crucible_api::OpenSetEventEnvelope {
                sequence: 4,
                at: crucible_api::OpenSetEventTime {
                    virtual_time_ticks: 17,
                    icount_retired: 23,
                    icount_node: Some(String::from("fixture-node")),
                },
                source: crucible_api::OpenSetEventSource::Node {
                    node: String::from("fixture-node"),
                },
                level: crucible::EventLevel::Info,
                observational: false,
                payload: crucible_api::OpenSetPayload::new(
                    "crucible.event.assertion_state_changed",
                    [
                        (String::from("id"), Text(assertion.id.name.clone())),
                        (String::from("new_state"), Text(String::from("Violated"))),
                    ]
                    .into_iter()
                    .collect(),
                ),
            },
        };
        let exact_frame = canonical_streaming_event_frame_bytes(&frame);
        let artifact = crucible::ContentHash::from_bytes(b"live-qemu-property-frame");
        let violation = qemu_property_violation_from_frames(&scenario, &[exact_frame], artifact)?;

        assert_eq!(violation.assertion, assertion.id);
        assert_eq!(violation.quantifier, assertion.quantifier_kind());
        assert_eq!(violation.at_virtual_time.ticks, 17);
        assert_eq!(violation.at_icount.map(|value| value.retired), Some(23));
        assert_eq!(
            violation.node.as_ref().map(|node| node.name.as_str()),
            Some("fixture-node")
        );
        assert_eq!(violation.reproduction_artifact, artifact);
        Ok(())
    }

    #[test]
    fn collect_fuzz_deduplicates_identical_phase_reproductions()
    -> Result<(), Box<dyn std::error::Error>> {
        let scenario = crucible::happy_path_scenario()?.scenario;
        let configuration = crucible::Configuration::genesis(scenario.scenario_def());
        let finding = crucible::FindingReproductionArtifact::capture(
            crucible::FindingDiscoveryPath::CoverageGuidedFuzzing,
            crucible::ContentHash::from_bytes(b"repeated-fuzz-timeout"),
            &scenario,
            &configuration,
        )?;
        let timeout = crucible_model::FailureTimeoutRecord::new(
            crucible_model::FailureTimeoutBudgetKind::ExecutionQuanta,
            Some(10),
            10,
            crucible::VirtualTime { ticks: 4 },
            None,
            None,
            finding.artifact.id(),
        );
        let evidence = crate::cli_triage_debug::triage_timeout_evidence(
            finding,
            timeout,
            crucible::ContentHash::from_bytes(b"repeated-fuzz-coverage"),
            Vec::new(),
        )?;
        let mut execution = QemuFuzzExecution::default();
        push_qemu_fuzz_finding(&mut execution, evidence.clone(), vec![1, 2, 3])?;
        let mut guided = QemuFuzzExecution::default();
        push_qemu_fuzz_finding(&mut guided, evidence.clone(), vec![1, 2, 3])?;
        merge_qemu_fuzz_execution(&mut execution, guided)?;
        assert_eq!(execution.findings.len(), 1);
        assert_eq!(execution.reproduction_artifacts.len(), 1);
        assert!(push_qemu_fuzz_finding(&mut execution, evidence, vec![4, 5, 6]).is_err());
        Ok(())
    }
}

fn qemu_fuzz_iteration_plan(sequence: u64, form: crucible::ScenarioDefForm) -> RunInvocationPlan {
    let scenario = form.scenario_def();
    RunInvocationPlan {
        request_seed: Some(scenario.seed()),
        save_store_root: None,
        scenario: RunScenarioRef::BuiltInExample {
            name: format!("fuzz-iteration-{sequence}"),
            form,
            scenario,
        },
        terminal_condition: RunTerminalCondition::Quiescence,
        max_virtual_time: None,
        max_virtual_time_ticks: None,
        max_quanta: None,
        execution_mode: RunExecutionMode::ToCompletion,
        save_policy: RunSavePolicy::Never,
        watch_streams_live_status: false,
        startup_commands: vec![SessionCommandKind::Start, SessionCommandKind::Continue],
        initial_control_commands: vec![SessionCommandKind::Query],
        accepted_interactive_commands: Vec::new(),
        observer_profile: VERIFY_BASELINE_PROFILE,
        collect_execution_fingerprints: true,
        bounded_ack_quanta: RUN_INTERACTIVE_ACK_QUANTA_BOUND,
        outcome_exit_codes: vec![
            (BackendCommandStatus::Passed, 0),
            (BackendCommandStatus::Failed, 1),
            (BackendCommandStatus::Timeout, 2),
            (BackendCommandStatus::Crashed, 3),
        ],
        invalid_scenario_exit_code: 4,
    }
}

#[path = "qemu_live/search.rs"]
mod search;

pub(crate) use search::*;
/// Runs one local scenario through the packaged QEMU backend.
pub(crate) fn run_local_qemu_workflow(
    backend: &ResolvedLocalBackend,
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    run_plan: &RunInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let mut run_plan = run_plan.clone();
    run_plan.collect_execution_fingerprints = true;
    let config = production_qemu_lifecycle_config(backend)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let control_plane = production_qemu_control_plane(config, run_plan.scenario.scenario_form());
    let client = InProcessLifecycleClient::new(control_plane);
    let report = if matches!(run_plan.execution_mode, RunExecutionMode::Interactive) {
        runtime.block_on(run_control_client_workflow_stdin_async(
            &client, &run_plan, false,
        ))?
    } else {
        runtime.block_on(run_control_client_workflow_async(&client, &run_plan, &[]))?
    };
    finish_run_workflow_outcome(thin_plan, backend_plan, ergonomics_plan, &run_plan, report)
}

/// Re-executes a v3 artifact through a fresh packaged-QEMU lifecycle session.
///
/// # Errors
///
/// Returns [`CliError`] when the contract is invalid, its branch recipe cannot
/// be reconstructed from the typed schedule, or the QEMU lifecycle fails.
pub(crate) fn run_live_qemu_artifact_replay(
    backend: &ResolvedLocalBackend,
    scenario: crucible::ScenarioDefForm,
    schedule: &crucible::Schedule,
    contract: &LiveQemuReplayContract,
) -> Result<(RunInvocationPlan, RunWorkflowReport), CliError> {
    let terminal_condition = match contract.terminal_condition.as_str() {
        "quiescence" => RunTerminalCondition::Quiescence,
        "virtual-time" => RunTerminalCondition::VirtualTime,
        "property" => RunTerminalCondition::Property,
        "stopped" => RunTerminalCondition::Stopped,
        other => {
            return Err(artifact_error(format!(
                "live-QEMU replay contract has unknown terminal condition `{other}`"
            )));
        }
    };
    let scenario_def = scenario.scenario_def();
    let mut startup_commands = contract
        .startup_controls
        .iter()
        .filter_map(|control| match control.command.as_str() {
            "start" => Some(SessionCommandKind::Start),
            "continue" => Some(SessionCommandKind::Continue),
            "step-quantum" => Some(SessionCommandKind::StepQuantum),
            _ => None,
        })
        .collect::<Vec<_>>();
    if startup_commands.is_empty() {
        startup_commands = vec![SessionCommandKind::Start, SessionCommandKind::Continue];
    }
    let initial_control_commands = contract
        .initial_controls
        .iter()
        .map(|_| SessionCommandKind::Query)
        .collect();
    let run_plan = RunInvocationPlan {
        request_seed: Some(scenario_def.seed()),
        save_store_root: None,
        scenario: RunScenarioRef::BuiltInExample {
            name: String::from("artifact-replay"),
            form: scenario.clone(),
            scenario: scenario_def.clone(),
        },
        terminal_condition,
        max_virtual_time: contract
            .max_virtual_time_ticks
            .map(|ticks| ticks.to_string()),
        max_virtual_time_ticks: contract.max_virtual_time_ticks,
        max_quanta: contract.max_quanta,
        execution_mode: RunExecutionMode::ToCompletion,
        save_policy: RunSavePolicy::Never,
        watch_streams_live_status: false,
        startup_commands,
        initial_control_commands,
        accepted_interactive_commands: Vec::new(),
        observer_profile: VERIFY_BASELINE_PROFILE,
        collect_execution_fingerprints: true,
        bounded_ack_quanta: RUN_INTERACTIVE_ACK_QUANTA_BOUND,
        outcome_exit_codes: vec![
            (BackendCommandStatus::Passed, 0),
            (BackendCommandStatus::Failed, 1),
            (BackendCommandStatus::Timeout, 2),
            (BackendCommandStatus::Crashed, 3),
        ],
        invalid_scenario_exit_code: 4,
    };
    let mut config = production_qemu_lifecycle_config(backend)?;
    if let Some(run_ceiling_icount) = contract.run_ceiling_icount {
        config = config.with_run_ceiling_icount(run_ceiling_icount);
    }
    if let Some(quantum_budget) = contract.lifecycle_quantum_budget {
        config = config.with_quantum_budget(quantum_budget);
    }
    let mut branch_evidence = None;
    match &contract.branch {
        LiveQemuReplayBranch::None => {}
        LiveQemuReplayBranch::Resume {
            base_decisions,
            frontier_ticks,
        } => {
            let base = replay_branch_base(&scenario_def, schedule, *base_decisions)?;
            branch_evidence = Some(replay_branch_evidence(
                &scenario,
                base.clone(),
                *frontier_ticks,
            )?);
            config = config.with_branch_prefix_overrides(
                base,
                VirtualTime {
                    ticks: *frontier_ticks,
                },
                Vec::new(),
            );
        }
        LiveQemuReplayBranch::Reseed {
            base_decisions,
            frontier_ticks,
            seed,
        } => {
            let base = replay_branch_base(&scenario_def, schedule, *base_decisions)?;
            branch_evidence = Some(replay_branch_evidence(
                &scenario,
                base.clone(),
                *frontier_ticks,
            )?);
            config = config.with_branch_reseed(
                base,
                VirtualTime {
                    ticks: *frontier_ticks,
                },
                crucible::Seed::from_u64(*seed),
            );
        }
        LiveQemuReplayBranch::PrefixOverrides {
            base_decisions,
            frontier_ticks,
            decision_start,
            decision_end,
        } => {
            let base = replay_branch_base(&scenario_def, schedule, *base_decisions)?;
            branch_evidence = Some(replay_branch_evidence(
                &scenario,
                base.clone(),
                *frontier_ticks,
            )?);
            let start = usize::try_from(*decision_start).map_err(|_| {
                artifact_error("live-QEMU replay override start cannot be represented")
            })?;
            let end = usize::try_from(*decision_end).map_err(|_| {
                artifact_error("live-QEMU replay override end cannot be represented")
            })?;
            if start != base.schedule.len() || end < start {
                return Err(artifact_error(
                    "live-QEMU replay override range is not contiguous with its branch base",
                ));
            }
            let overrides = schedule.decisions().get(start..end).ok_or_else(|| {
                artifact_error("live-QEMU replay override range exceeds the model schedule")
            })?;
            if overrides
                .iter()
                .any(|decision| !matches!(decision, crucible::Decision::Override(_)))
            {
                return Err(artifact_error(
                    "live-QEMU replay branch recipe contains a non-override decision",
                ));
            }
            config = config.with_branch_prefix_overrides(
                base,
                VirtualTime {
                    ticks: *frontier_ticks,
                },
                overrides.to_vec(),
            );
        }
    }
    let fault_choices = replay_indexed_fault_choices(schedule, &contract.fault_choice_indices)?;
    let network_choices =
        replay_indexed_network_choices(schedule, &contract.network_choice_indices)?;
    if !fault_choices.is_empty() {
        config = config.with_branch_fault_choices(fault_choices);
    }
    if !network_choices.is_empty() {
        config = config.with_branch_network_choices(network_choices);
    }
    if contract.coverage {
        config = config.with_coverage(production_api::ProductionPluginSwitch::On);
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let control_plane = production_qemu_control_plane(config, &scenario);
    let client = InProcessLifecycleClient::new(control_plane);
    let report = if contract.producer == "fork" {
        let evidence = branch_evidence.ok_or_else(|| {
            artifact_error("live-QEMU fork replay contract requires branch evidence")
        })?;
        let resume_plan = ResumeInvocationPlan {
            savepoint: ResumeSavepointRef::CheckpointHash(evidence.checkpoint.id),
            store_root: PathBuf::new(),
            terminal_condition,
            max_virtual_time: contract
                .max_virtual_time_ticks
                .map(|ticks| ticks.to_string()),
            max_virtual_time_ticks: contract.max_virtual_time_ticks,
            execution_mode: RunExecutionMode::ToCompletion,
            watch_streams_live_status: false,
            startup_commands: vec![SessionCommandKind::Fork, SessionCommandKind::Continue],
            initial_control_commands: vec![SessionCommandKind::Query],
            accepted_interactive_commands: Vec::new(),
        };
        runtime
            .block_on(
                run_remote_control_client_resume_from_evidence_with_driver_async(
                    &client,
                    &resume_plan,
                    evidence,
                    ResumeInteractiveCommandDriver::Preparsed(&[]),
                    replay_has_exact_branch_choices(
                        &contract.fault_choice_indices,
                        &contract.network_choice_indices,
                    ),
                ),
            )?
            .run
    } else {
        runtime.block_on(run_control_client_workflow_with_interactive_driver(
            &client,
            &run_plan,
            InteractiveCommandDriver::Preparsed(&[]),
            false,
            replay_has_exact_branch_choices(
                &contract.fault_choice_indices,
                &contract.network_choice_indices,
            ),
        ))?
    };
    Ok((run_plan, report))
}

fn replay_has_exact_branch_choices(fault_indices: &[u64], network_indices: &[u64]) -> bool {
    !fault_indices.is_empty() || !network_indices.is_empty()
}

fn replay_branch_evidence(
    scenario_form: &crucible::ScenarioDefForm,
    configuration: crucible::Configuration,
    frontier_ticks: u64,
) -> Result<ResumeHandleEvidence, CliError> {
    let frontier = validate_resume_handle_frontier(&configuration.schedule, frontier_ticks)?;
    let checkpoint = checkpoint_for_resume_configuration(&configuration, frontier)?;
    Ok(ResumeHandleEvidence {
        scenario_form: scenario_form.clone(),
        scenario: scenario_form.scenario_def(),
        schedule: configuration.schedule.clone(),
        configuration,
        checkpoint,
    })
}

fn replay_branch_base(
    scenario: &crucible::ScenarioDef,
    schedule: &crucible::Schedule,
    decisions: u64,
) -> Result<crucible::Configuration, CliError> {
    let decisions = usize::try_from(decisions)
        .map_err(|_| artifact_error("live-QEMU branch base length cannot be represented"))?;
    let prefix = schedule.prefix(decisions).map_err(|error| {
        artifact_error(format!("construct live-QEMU replay branch prefix: {error}"))
    })?;
    Ok(crucible::Configuration {
        def: scenario.clone(),
        schedule: prefix,
    })
}

fn replay_indexed_fault_choices(
    schedule: &crucible::Schedule,
    indices: &[u64],
) -> Result<Vec<crucible::Decision>, CliError> {
    let mut choices = Vec::with_capacity(indices.len().saturating_mul(2));
    for index in indices {
        let index = usize::try_from(*index)
            .map_err(|_| artifact_error("fault choice index cannot be represented"))?;
        let pair = schedule
            .decisions()
            .get(index..index.saturating_add(2))
            .ok_or_else(|| artifact_error("fault choice index exceeds the model schedule"))?;
        if !matches!(pair[0], crucible::Decision::RngDraw(_))
            || !matches!(pair[1], crucible::Decision::FaultFires(_))
        {
            return Err(artifact_error(
                "fault choice index does not identify an RNG/fault decision pair",
            ));
        }
        choices.extend_from_slice(pair);
    }
    Ok(choices)
}

fn replay_indexed_network_choices(
    schedule: &crucible::Schedule,
    indices: &[u64],
) -> Result<Vec<crucible::OverrideDecision>, CliError> {
    indices
        .iter()
        .map(|index| {
            let index = usize::try_from(*index)
                .map_err(|_| artifact_error("network choice index cannot be represented"))?;
            match schedule.decisions().get(index) {
                Some(crucible::Decision::Override(decision))
                    if decision.point.key.starts_with("live-world-network/") =>
                {
                    Ok(decision.clone())
                }
                _ => Err(artifact_error(
                    "network choice index does not identify a live-world network override",
                )),
            }
        })
        .collect()
}

/// Verifies every reduction through an independent packaged-QEMU session.
pub(crate) fn run_local_qemu_verify_workflow(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    verify_plan: &VerifyInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let backend = backend_plan
        .resolved_backend
        .as_ref()
        .ok_or_else(|| backend_error("local QEMU verify requires a resolved backend"))?;
    let scenario = verify_plan.scenario().ok_or_else(|| {
        backend_error("QEMU verify compare mode must use the artifact comparison path")
    })?;
    let config = production_qemu_lifecycle_config(backend)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let control_plane = production_qemu_control_plane(config, scenario.scenario_form());
    let client = InProcessLifecycleClient::new(control_plane);
    let report = runtime.block_on(run_control_client_verify_workflow_async(
        &client,
        verify_plan,
        Some(backend),
        ergonomics_plan,
    ))?;
    finish_verify_workflow_outcome(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        verify_plan,
        report,
    )
}

pub(crate) fn production_qemu_control_plane(
    config: production_api::ProductionVmLifecycleConfig,
    source: &crucible::ScenarioDefForm,
) -> LifecycleControlPlane<
    production_api::ProductionVmLifecycleLoop,
    production_api::LifecycleLoopFactory<production_api::ProductionVmLifecycleLoop>,
> {
    let white_box_policies = source
        .world()
        .vm_nodes()
        .iter()
        .map(|node| (node.id.clone(), node.white_box))
        .collect::<BTreeMap<_, _>>();
    LifecycleControlPlane::new_with_fallible_source_factory(
        "crucible-cli-qemu",
        Vec::new(),
        move |scenario, source, _seed| {
            let source = source.ok_or_else(|| production_api::LifecycleApiError::LoopFactory {
                message: String::from(
                    "production QEMU lifecycle requires an inline scenario definition",
                ),
            })?;
            production_api::build_production_vm_lifecycle_loop(scenario, source, &config)
        },
    )
    .with_thin_replay_resume()
    .with_white_box_policy_provider(move |_scenario| white_box_policies.clone())
}

pub(crate) fn production_qemu_lifecycle_config(
    backend: &ResolvedLocalBackend,
) -> Result<production_api::ProductionVmLifecycleConfig, CliError> {
    let (qemu, plugin) = match backend {
        ResolvedLocalBackend::Qemu { qemu, plugin, .. } => (qemu, plugin),
        #[cfg(any(test, feature = "test-double"))]
        ResolvedLocalBackend::Double => {
            return Err(backend_error(
                "production QEMU lifecycle requires the QEMU backend",
            ));
        }
    };
    let kernel = required_live_qemu_asset(
        "CRUCIBLE_KERNEL",
        option_env!("CRUCIBLE_AOS_KERNEL"),
        "kernel",
    )?;
    let root_image = required_live_qemu_asset(
        "CRUCIBLE_ROOT_IMAGE",
        option_env!("CRUCIBLE_AOS_ROOT_IMAGE"),
        "root image",
    )?;
    let mut config =
        production_api::ProductionVmLifecycleConfig::new(qemu, plugin, kernel, root_image)
            .with_root_image_format(production_api::ProductionRootImageFormat::Raw)
            .with_run_ceiling_icount(PRODUCTION_CLI_RUN_CEILING_ICOUNT)
            .with_quantum_budget(PRODUCTION_CLI_QUANTUM_BUDGET)
            .with_completion_timeout(PRODUCTION_CLI_COMPLETION_TIMEOUT);
    if let Some(kernel_cmdline) = live_qemu_kernel_cmdline() {
        config = config.with_kernel_cmdline_prefix(kernel_cmdline);
    }
    if let Some(initrd) = optional_live_qemu_asset(
        "CRUCIBLE_INITRD",
        option_env!("CRUCIBLE_AOS_INITRD"),
        "initrd",
    )? {
        config = config.with_initrd(initrd);
    }
    if let Some(gateway) =
        optional_live_qemu_asset("CRUCIBLE_DEBUG_GATEWAY", None, "debugger gateway")?
    {
        config = config.with_debug_gateway(gateway);
    }
    Ok(config)
}

pub(crate) fn append_qemu_control_plane_execution_proof(
    outcome: &mut BackendCommandOutcome,
    backend: &ResolvedLocalBackend,
    operation: &'static str,
) {
    let (qemu_build_id, plugin_abi) = match backend {
        ResolvedLocalBackend::Qemu {
            qemu_build_id,
            plugin_abi,
            ..
        } => (qemu_build_id, plugin_abi),
        #[cfg(any(test, feature = "test-double"))]
        ResolvedLocalBackend::Double => return,
    };
    outcome.stdout.push(format!(
        "qemu-live\toperation={operation}\tqemu_build_id={qemu_build_id}\tplugin_abi={plugin_abi}"
    ));
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("qemu"),
        kind: String::from("live_backend_execution"),
        summary: format!(
            "operation={operation} qemu_build_id={qemu_build_id} plugin_abi={plugin_abi}"
        ),
    });
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_validates_fault_only_and_network_only_choice_streams() {
        assert!(!replay_has_exact_branch_choices(&[], &[]));
        assert!(replay_has_exact_branch_choices(&[3], &[]));
        assert!(replay_has_exact_branch_choices(&[], &[5]));
        assert!(replay_has_exact_branch_choices(&[3], &[5]));
    }

    #[test]
    fn fork_replay_reconstructs_resumable_branch_evidence() -> Result<(), Box<dyn Error>> {
        let scenario = crucible::happy_path_scenario()?.scenario;
        let schedule = Schedule::from_decisions((1..=2).map(|ticks| {
            crucible::Decision::DeliveryOrder(crucible::DeliveryOrderDecision {
                at: VirtualTime { ticks },
                order: Vec::new(),
            })
        }));
        let base = replay_branch_base(&scenario.scenario_def(), &schedule, 1)?;
        let evidence = replay_branch_evidence(&scenario, base, 1)?;

        assert_eq!(evidence.schedule.len(), 1);
        assert_eq!(evidence.checkpoint.virtual_time.ticks, 1);
        assert_eq!(evidence.configuration.id(), evidence.checkpoint.id);
        assert_eq!(evidence.scenario_form.id(), scenario.id());
        Ok(())
    }

    #[test]
    fn fork_replay_rejects_frontier_beyond_retained_prefix() -> Result<(), Box<dyn Error>> {
        let scenario = crucible::happy_path_scenario()?.scenario;
        let schedule = Schedule::from_decisions([crucible::Decision::DeliveryOrder(
            crucible::DeliveryOrderDecision {
                at: VirtualTime { ticks: 1 },
                order: Vec::new(),
            },
        )]);
        let base = replay_branch_base(&scenario.scenario_def(), &schedule, 1)?;
        let error = replay_branch_evidence(&scenario, base, 2)
            .expect_err("unrecorded branch frontier must fail closed");

        assert!(error.to_string().contains("exceeded the latest recorded"));
        Ok(())
    }
}
