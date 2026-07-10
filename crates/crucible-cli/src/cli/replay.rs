// Replay execution, schedule-prefix proof, and bisection.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TraceRenderReport {
    format: OutputFormat,
    path: Option<PathBuf>,
    bytes: Vec<u8>,
    entry_count: usize,
    streamed_entries: usize,
    canonical_digest: String,
}

fn emit_canonical_trace(
    format: OutputFormat,
    entries: &[CanonicalLogEntry],
    trace_path: Option<&Path>,
    stdout: bool,
) -> Result<TraceRenderReport, CliError> {
    if format == OutputFormat::Markdown {
        return Err(usage_error(
            "--format markdown is reserved for triage reports, not canonical event-log traces",
        ));
    }

    let mut bytes = Vec::new();
    let mut streamed_entries = 0usize;
    match format {
        OutputFormat::Jsonl => {
            let mut trace_file = trace_path.map(fs::File::create).transpose()?;
            for entry in entries {
                let line = json_for_canonical_log_entry(entry);
                if stdout {
                    println!("{line}");
                }
                if let Some(file) = trace_file.as_mut() {
                    writeln!(file, "{line}")?;
                }
                writeln!(&mut bytes, "{line}")?;
                streamed_entries += 1;
            }
        }
        OutputFormat::Json | OutputFormat::Table => {
            let rendered = render_canonical_event_log(format, entries)?;
            if stdout {
                println!("{}", String::from_utf8_lossy(&rendered.bytes));
            }
            if let Some(path) = trace_path {
                fs::write(path, &rendered.bytes)?;
            }
            bytes = rendered.bytes;
        }
        OutputFormat::Markdown => unreachable!("markdown rejected above"),
    }

    Ok(TraceRenderReport {
        format,
        path: trace_path.map(Path::to_path_buf),
        bytes,
        entry_count: entries.len(),
        streamed_entries,
        canonical_digest: canonical_log_digest(entries),
    })
}

fn replay_reproduction_artifact(
    cli: &Cli,
    args: &ReplayArgs,
) -> Result<ReplayArtifactReport, CliError> {
    let bytes = fs::read(&args.artifact)?;
    let artifact = validate_replayable_reproduction_artifact(cli, &bytes)?;
    let seed = artifact.seed;
    let scenario_digest = artifact.scenario.digest.clone();
    let to_savepoint = args
        .to
        .as_deref()
        .map(|target| replay_to_savepoint(cli, target, &artifact))
        .transpose()?;
    let check = if let Some(path) = &args.check {
        let canonical_log = canonical_log_entries_from_artifact(&artifact)?;
        let canonical_log_bytes = canonical_log_entry_bytes(&canonical_log);
        let original = fs::read(path)?;
        let mismatch = (original != canonical_log_bytes).then(|| ReplayCheckMismatchReport {
            original_digest: content_address_bytes(&original),
            replayed_digest: content_address_bytes(&canonical_log_bytes),
            first_diff_byte: bisect_first_different_byte(&original, &canonical_log_bytes),
            original_len: original.len(),
            replayed_len: canonical_log_bytes.len(),
        });
        Some(ReplayCheckReport {
            path: path.clone(),
            digest: content_address_bytes(&canonical_log_bytes),
            mismatch,
        })
    } else {
        None
    };
    let bisect = if check
        .as_ref()
        .and_then(|check| check.mismatch.as_ref())
        .is_some()
    {
        None
    } else {
        args.bisect
            .as_ref()
            .map(|other| replay_bisect_artifacts(cli, other, &artifact, &bytes))
            .transpose()?
    };
    Ok(ReplayArtifactReport {
        path: args.artifact.clone(),
        digest: content_address_bytes(&bytes),
        seed,
        scenario_digest,
        to_savepoint,
        check,
        bisect,
    })
}

fn replay_to_savepoint(
    cli: &Cli,
    target: &str,
    artifact: &CliReproductionArtifact,
) -> Result<ReplayToSavepointReport, CliError> {
    let savepoint = resolve_savepoint_ref("replay --to", Some(target))?;
    let evidence = savepoint_evidence("replay --to", &savepoint, &default_run_store_root(cli))?;
    let evidence_scenario_digest =
        content_address_bytes(&scenario_identity_bytes(&evidence.scenario));
    if evidence_scenario_digest != artifact.scenario.digest {
        return Err(artifact_error(format!(
            "replay --to savepoint scenario {} did not match artifact scenario {}",
            evidence_scenario_digest, artifact.scenario.digest
        )));
    }
    let schedule_prefix = prove_replay_schedule_prefix(artifact, &evidence.schedule)?;
    let oracle = validate_checkpoint_with_replay_oracle(
        "replay --to",
        &evidence.scenario,
        &evidence.configuration,
        &evidence.checkpoint,
        evidence.checkpoint.virtual_time,
    )?;
    let materialization =
        materialize_replay_to_savepoint(&evidence.scenario, &evidence.configuration, &oracle)?;
    Ok(ReplayToSavepointReport {
        target_label: savepoint.label(),
        checkpoint: evidence.checkpoint.id,
        frontier_ticks: evidence.checkpoint.virtual_time.ticks,
        schedule_prefix,
        oracle,
        materialization,
    })
}

fn prove_replay_schedule_prefix(
    artifact: &CliReproductionArtifact,
    target_schedule: &Schedule,
) -> Result<ReplaySchedulePrefixProof, CliError> {
    let target_decisions = target_schedule.len();
    if target_decisions > artifact.decisions.len() {
        return Err(CliError::ReplayCheck(format!(
            "replay --to savepoint frontier has {target_decisions} decisions, but artifact encodes only {} decisions",
            artifact.decisions.len()
        )));
    }

    let expected = replay_schedule_prefix_decisions(target_schedule);
    for (index, expected_decision) in expected.iter().enumerate() {
        let actual = &artifact.decisions[index];
        let actual_payload_summary = decision_payload_summary(artifact, actual)?;
        if !replay_schedule_prefix_decision_matches(
            actual,
            &actual_payload_summary,
            expected_decision,
        ) {
            return Err(CliError::ReplayCheck(format!(
                "replay --to schedule-prefix mismatch at decision {index}: expected sequence={} virtual_time={} kind={} payload={}, got sequence={} virtual_time={} kind={} payload={}",
                expected_decision.sequence,
                expected_decision.virtual_time_ticks,
                expected_decision.kind,
                expected_decision.payload_digest,
                actual.sequence,
                actual.virtual_time_ticks,
                actual.kind,
                actual.payload_digest
            )));
        }
    }

    Ok(ReplaySchedulePrefixProof {
        target_decisions,
        artifact_decisions: artifact.decisions.len(),
        matched_decisions: expected.len(),
        typed_prefix_digest: typed_schedule_prefix_digest(&expected),
        artifact_prefix_digest: schedule_digest(&artifact.decisions[..target_decisions]),
    })
}

fn replay_schedule_prefix_decisions(schedule: &Schedule) -> Vec<ReplaySchedulePrefixDecisionProof> {
    schedule
        .decisions()
        .iter()
        .enumerate()
        .map(|(index, decision)| {
            let payload_summary = format!("{decision:?}");
            ReplaySchedulePrefixDecisionProof {
                sequence: index as u64,
                virtual_time_ticks: index as u64 + 1,
                kind: engine_decision_kind(decision).to_string(),
                payload_digest: content_address_bytes(payload_summary.as_bytes()),
                payload_summary,
            }
        })
        .collect()
}

fn replay_schedule_prefix_decision_matches(
    actual: &CliDecision,
    actual_payload_summary: &str,
    expected: &ReplaySchedulePrefixDecisionProof,
) -> bool {
    actual.sequence == expected.sequence
        && actual.virtual_time_ticks == expected.virtual_time_ticks
        && replay_schedule_prefix_kind_matches(&actual.kind, &expected.kind)
        && actual.payload_digest == expected.payload_digest
        && actual_payload_summary == expected.payload_summary
}

fn replay_schedule_prefix_kind_matches(actual: &str, expected: &str) -> bool {
    actual == expected || actual == expected.replace('-', "_")
}

fn typed_schedule_prefix_digest(decisions: &[ReplaySchedulePrefixDecisionProof]) -> String {
    let mut material = String::new();
    artifact_line(
        &mut material,
        &["schema", REPLAY_SCHEDULE_PREFIX_PROOF_SCHEMA],
    );
    for decision in decisions {
        artifact_line(
            &mut material,
            &[
                "typed-decision",
                &decision.sequence.to_string(),
                &decision.virtual_time_ticks.to_string(),
                &decision.kind,
                &decision.payload_digest,
            ],
        );
    }
    content_address_bytes(material.as_bytes())
}

fn replay_to_savepoint_status_line(target: &ReplayToSavepointReport) -> String {
    format!(
        "crucible: replay --to {} status=target-validated schedule_prefix=typed materialization={} unified_operation={} checkpoint={} frontier_ticks={} target_decisions={} artifact_decisions={} matched_decisions={} typed_prefix_digest={} artifact_prefix_digest={} materialized_configuration={} materialized_schedule={} materialized_checkpoint={} runtime_state={} reduced_state={} single_vm_fingerprint={} graph={} replay_fat={} replay_thin={} oracle={} store_objects={}",
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

fn materialize_replay_to_savepoint(
    scenario: &crucible::ScenarioDef,
    configuration: &crucible::Configuration,
    oracle: &SavepointOracleProof,
) -> Result<ReplayToSavepointMaterializationProof, CliError> {
    let mut graph = save_validation_graph(scenario)?;
    let replay = crucible::ReplayOracleCheck {
        configuration: oracle.configuration,
        fat_checkpoint: oracle.fat_checkpoint,
        thin_checkpoint: oracle.thin_checkpoint,
    };
    let report = graph
        .validate_unified_operation(&crucible::UnifiedGraphOperationEvidence::Replay {
            configuration: configuration.clone(),
            replay,
        })
        .map_err(|error| {
            CliError::Identity(format!(
                "replay --to materialized temporal-graph replay failed: {error}"
            ))
        })?;
    if report.operation != crucible::UnifiedGraphOperationKind::Replay {
        return Err(CliError::Identity(format!(
            "replay --to materialized unexpected unified operation {:?}",
            report.operation
        )));
    }
    Ok(ReplayToSavepointMaterializationProof::from_report(report))
}

fn replay_bisect_artifacts(
    cli: &Cli,
    other_path: &Path,
    artifact: &CliReproductionArtifact,
    artifact_bytes: &[u8],
) -> Result<ReplayBisectionReport, CliError> {
    let other_bytes = fs::read(other_path)?;
    let other_artifact = validate_replayable_reproduction_artifact(cli, &other_bytes)?;
    verify_compare_artifact_inputs_match("replay --bisect", artifact, &other_artifact)?;
    let mode = VerifyMode::CompareArtifacts {
        left: PathBuf::from("replay-left"),
        right: other_path.to_path_buf(),
    };
    let reductions = verify_reduction_plans(2, false, &mode);
    let mut reductions = reductions.into_iter();
    let left_reduction = reductions
        .next()
        .ok_or_else(|| backend_error("replay bisection omitted left reduction"))?;
    let right_reduction = reductions
        .next()
        .ok_or_else(|| backend_error("replay bisection omitted right reduction"))?;
    let witnesses = vec![
        verify_witness_from_artifact(left_reduction, artifact.clone(), artifact_bytes.to_vec())?,
        verify_witness_from_artifact(right_reduction, other_artifact, other_bytes.clone())?,
    ];
    let divergence = compare_verify_witnesses(&witnesses);
    Ok(ReplayBisectionReport {
        other_path: other_path.to_path_buf(),
        other_digest: content_address_bytes(&other_bytes),
        divergence,
    })
}

fn replay_bisect_error(
    left_path: &Path,
    bisect: &ReplayBisectionReport,
    divergence: &VerifyDivergenceReport,
) -> CliError {
    CliError::ReplayCheck(format!(
        "replay --bisect divergence between `{}` and `{}`: mismatch={}, first_decision={}, first_fingerprint_sample={}, first_instruction={}, node={}, first_diff_byte={}, left_state={}, right_state={}",
        left_path.display(),
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
        divergence.first_different_instruction,
        divergence.node.as_deref().unwrap_or("unknown"),
        divergence.first_different_byte,
        divergence.left_state_digest,
        divergence.right_state_digest
    ))
}

fn replay_check_mismatch_error(
    check: &ReplayCheckReport,
    mismatch: &ReplayCheckMismatchReport,
) -> CliError {
    CliError::ReplayCheck(format!(
        "replay --check mismatch for `{}`: expected {}, replayed {}, first_diff_byte={}, original_len={}, replayed_len={}",
        check.path.display(),
        mismatch.original_digest,
        mismatch.replayed_digest,
        mismatch.first_diff_byte,
        mismatch.original_len,
        mismatch.replayed_len
    ))
}

fn write_failure_reproduction_artifact(
    cli: &Cli,
    artifact_bytes: &[u8],
    failure_slug: &str,
) -> Result<FailureArtifactReport, CliError> {
    validate_replayable_reproduction_artifact(cli, artifact_bytes)?;
    let digest = content_address_bytes(artifact_bytes);
    fs::create_dir_all(&cli.artifact_dir)?;
    let file_name = format!(
        "repro-{}-{}.crucible",
        sanitize_slug(failure_slug),
        short_digest(&digest)
    );
    let path = cli.artifact_dir.join(file_name);
    fs::write(&path, artifact_bytes)?;
    let footer = failure_reproduction_footer(path.clone());

    Ok(FailureArtifactReport {
        path,
        digest,
        footer,
    })
}
