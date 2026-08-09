//! Remote resume, fork, run, save, and verification workflows.

use super::*;

pub(in super::super) fn run_remote_workflow(
    daemon: &str,
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    run_plan: &RunInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let client = remote_rpc_client(daemon, backend_plan)?;
    let report = if matches!(run_plan.execution_mode, RunExecutionMode::Interactive) {
        runtime.block_on(run_control_client_workflow_stdin_async(
            &client, run_plan, true,
        ))?
    } else {
        runtime.block_on(run_control_client_workflow_async(&client, run_plan, &[]))?
    };
    finish_run_workflow_outcome(thin_plan, backend_plan, ergonomics_plan, run_plan, report)
}

pub(in super::super) fn run_remote_verify_workflow(
    daemon: &str,
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    verify_plan: &VerifyInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let report = match &verify_plan.mode {
        VerifyMode::RunScenario { .. } => {
            let client = remote_rpc_client(daemon, backend_plan)?;
            runtime.block_on(run_control_client_verify_workflow_async(
                &client,
                verify_plan,
                backend_plan.resolved_backend.as_ref(),
                ergonomics_plan,
            ))?
        }
        VerifyMode::CompareArtifacts { .. } => verify_compare_artifacts(verify_plan)?,
    };
    finish_verify_workflow_outcome(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        verify_plan,
        report,
    )
}

pub(in super::super) fn run_remote_save_workflow(
    daemon: &str,
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    save_plan: &SaveInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let client = remote_rpc_client(daemon, backend_plan)?;
    let report = runtime.block_on(run_remote_control_client_save_workflow_async(
        &client, save_plan,
    ))?;
    finish_save_workflow_outcome(thin_plan, backend_plan, ergonomics_plan, save_plan, report)
}

pub(in super::super) fn run_remote_resume_workflow(
    daemon: &str,
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    resume_plan: &ResumeInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let client = remote_rpc_client(daemon, backend_plan)?;
    let report = runtime.block_on(run_remote_control_client_resume_workflow_async(
        &client,
        resume_plan,
    ))?;
    finish_resume_workflow_outcome(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        resume_plan,
        report,
    )
}

#[cfg(test)]
pub(in super::super) fn run_remote_resume_workflow_with_interactive_commands(
    daemon: &str,
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    resume_plan: &ResumeInvocationPlan,
    commands: &[SessionCommandKind],
) -> Result<BackendCommandOutcome, CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let client = remote_rpc_client(daemon, backend_plan)?;
    let report = runtime.block_on(run_remote_control_client_resume_workflow_with_driver_async(
        &client,
        resume_plan,
        ResumeInteractiveCommandDriver::Preparsed(commands),
    ))?;
    finish_resume_workflow_outcome(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        resume_plan,
        report,
    )
}

pub(in super::super) fn daemon_rpc_endpoint(daemon: &str) -> String {
    if daemon.contains("://") {
        daemon.to_string()
    } else {
        format!("http://{daemon}")
    }
}

pub(in super::super) fn remote_rpc_client(
    daemon: &str,
    backend_plan: &BackendSelectionPlan,
) -> Result<RpcControlClient, CliError> {
    let endpoint = RpcEndpoint::http2(daemon_rpc_endpoint(daemon));
    let Some(paths) = backend_plan.daemon_security.as_ref() else {
        return RpcControlClient::new(endpoint).map_err(control_client_error);
    };
    let server_ca = fs::read(&paths.server_ca).map_err(|error| {
        control_client_error(crucible_api::ControlClientError::HttpClientBuild {
            message: format!(
                "cannot read daemon CA certificate {}: {error}",
                paths.server_ca.display()
            ),
        })
    })?;
    let mut client_identity = fs::read(&paths.client_certificate).map_err(|error| {
        control_client_error(crucible_api::ControlClientError::HttpClientBuild {
            message: format!(
                "cannot read daemon client certificate {}: {error}",
                paths.client_certificate.display()
            ),
        })
    })?;
    if !client_identity.ends_with(b"\n") {
        client_identity.push(b'\n');
    }
    let private_key = fs::read(&paths.client_private_key).map_err(|error| {
        control_client_error(crucible_api::ControlClientError::HttpClientBuild {
            message: format!(
                "cannot read daemon client private key {}: {error}",
                paths.client_private_key.display()
            ),
        })
    })?;
    client_identity.extend_from_slice(&private_key);
    RpcControlClient::new_mtls(
        endpoint,
        RpcMutualTlsConfig::from_pem(server_ca, client_identity),
    )
    .map_err(control_client_error)
}

pub(in super::super) fn finish_run_workflow_outcome(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    run_plan: &RunInvocationPlan,
    report: RunWorkflowReport,
) -> Result<BackendCommandOutcome, CliError> {
    let mut outcome = backend_command_outcome(thin_plan, backend_plan, ergonomics_plan);
    outcome.status = report.status;
    outcome.exit_code = report.status.exit_code();
    outcome.stdout.push(format!(
        "run-session\tcreated={}\tfinal={}\toutcome={}\tsavepoint={}\tfrontier_ticks={}\tquanta={}\tevents={}\tacks={}",
        report.created_state,
        report.final_state,
        terminal_outcome_label(report.outcome),
        report
            .terminal_savepoint
            .map(format_content_hash_ref)
            .unwrap_or_else(|| String::from("none")),
        report.final_frontier_ticks,
        report.final_quanta,
        report.streamed_events.len(),
        report.acknowledged_commands.len()
    ));
    for status in &report.watch_statuses {
        outcome.stdout.push(format!("run-watch\t{status}"));
    }
    append_local_double_run_entries(&mut outcome, run_plan, &report);
    if let Some(savepoint) = run_terminal_savepoint_for_policy(run_plan, &report)? {
        let store_root = run_plan
            .save_store_root
            .as_ref()
            .ok_or_else(|| backend_error("run save policy required a configured DAG store"))?;
        let terminal_configuration = report.terminal_configuration.as_ref().ok_or_else(|| {
            backend_error("run save policy required a terminal configuration for persistence")
        })?;
        let store_report = persist_checkpoint_closure_artifact(
            store_root,
            run_plan.scenario.scenario_form(),
            terminal_configuration,
            crucible::VirtualTime {
                ticks: report.final_frontier_ticks,
            },
            savepoint,
        )?;
        outcome.terminal_savepoint = Some(savepoint);
        let savepoint = format_content_hash_ref(savepoint);
        outcome.stdout.push(format!(
            "run-savepoint\tpolicy={}\tcheckpoint={}\tfinal={}\toutcome={}",
            run_save_policy_label(run_plan.save_policy),
            savepoint,
            report.final_state,
            terminal_outcome_label(report.outcome)
        ));
        outcome.stdout.push(format!(
            "run-store\tcheckpoint={}\tartifact={}\tindex={}\tstore={}",
            savepoint,
            format_content_hash_ref(store_report.artifact),
            format_content_hash_ref(store_report.index),
            store_root.display()
        ));
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: String::from("session"),
            kind: String::from("run_savepoint"),
            summary: format!(
                "policy={} checkpoint={} outcome={}",
                run_save_policy_label(run_plan.save_policy),
                savepoint,
                terminal_outcome_label(report.outcome)
            ),
        });
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: String::from("session"),
            kind: String::from("run_savepoint_store"),
            summary: format!(
                "checkpoint={} artifact={} index={}",
                savepoint,
                format_content_hash_ref(store_report.artifact),
                format_content_hash_ref(store_report.index)
            ),
        });
        outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
    }
    if outcome.status.is_non_passing() && backend_plan.target == BackendExecutionTarget::Local {
        let artifact_seed = ergonomics_plan
            .map(|plan| plan.seed.value)
            .unwrap_or_else(|| {
                seed_to_u64(
                    run_plan
                        .request_seed
                        .unwrap_or_else(|| run_plan.scenario.scenario_def().seed()),
                )
            });
        let artifact = run_failure_reproduction_artifact_bytes(
            artifact_seed,
            backend_plan.resolved_backend.as_ref(),
            run_plan,
            &report,
            &outcome.canonical_log,
        )?;
        outcome.artifact_digest = content_address_bytes(&artifact);
        outcome.reproduction_artifact = Some(artifact);
    }
    Ok(outcome)
}

pub(in super::super) fn finish_save_workflow_outcome(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    save_plan: &SaveInvocationPlan,
    report: SaveWorkflowReport,
) -> Result<BackendCommandOutcome, CliError> {
    let SaveWorkflowReport {
        run,
        oracle,
        boundary_evidence,
    } = report;
    let mut outcome = finish_run_workflow_outcome(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        &save_plan.run_plan,
        run,
    )?;
    outcome.terminal_savepoint = Some(oracle.fat_checkpoint);
    outcome.stdout.push(format!(
        "save-boundary\t{}",
        boundary_evidence.canonical_summary()
    ));
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("control"),
        kind: String::from("save_boundary_proof"),
        summary: boundary_evidence.canonical_summary(),
    });
    outcome.stdout.push(format!(
        "save-oracle\tstatus={}\tconfiguration={}\tfat={}\tthin={}\tstore_objects={}",
        oracle.status_label(),
        format_content_hash_ref(oracle.configuration),
        format_content_hash_ref(oracle.fat_checkpoint),
        format_content_hash_ref(oracle.thin_checkpoint),
        oracle.store_objects
    ));
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("replay-oracle"),
        kind: String::from("save_oracle_validation"),
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
    outcome.save_boundary_evidence = Some(boundary_evidence);
    Ok(outcome)
}

pub(in super::super) fn finish_verify_workflow_outcome(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    verify_plan: &VerifyInvocationPlan,
    report: VerifyWorkflowReport,
) -> Result<BackendCommandOutcome, CliError> {
    let mut outcome = backend_command_outcome(thin_plan, backend_plan, ergonomics_plan);
    outcome.stdout.push(format!(
        "verify-plan\tmode={}\truns={}\treductions={}\tadversarial={}\tbisect={}",
        verify_plan.mode.label(),
        verify_plan.requested_runs,
        report.witnesses.len(),
        verify_plan.applies_hostile_condition_matrix,
        verify_plan.bisection_on_divergence
    ));
    for witness in &report.witnesses {
        let canonical_log_digest = content_address_bytes(&witness.canonical_log_bytes);
        let fingerprint_digest = content_address_bytes(&witness.fingerprint_stream);
        outcome.stdout.push(format!(
            "verify-run\tindex={}\trun={}\tprofile={}\tcanonical_log={}\tfingerprint={}\tsamples={}",
            witness.reduction.index,
            witness.reduction.run_index,
            witness.reduction.host_profile.label(),
            canonical_log_digest,
            fingerprint_digest,
            witness.fingerprint_samples.len()
        ));
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: String::from("verify"),
            kind: String::from("independent_reduction"),
            summary: format!(
                "index={} run={} profile={} canonical_log={} fingerprint={} samples={}",
                witness.reduction.index,
                witness.reduction.run_index,
                witness.reduction.host_profile.label(),
                canonical_log_digest,
                fingerprint_digest,
                witness.fingerprint_samples.len()
            ),
        });
    }
    if let Some(divergence) = report.divergence {
        outcome.status = BackendCommandStatus::Failed;
        outcome.exit_code = outcome.status.exit_code();
        outcome.stdout.push(format!(
            "verify-divergence\tleft={}\tright={}\tmismatch={}\tfirst_decision={}\tfirst_fingerprint_sample={}\tfirst_virtual_time={}\tfirst_virtual_time_node={}\tfirst_instruction={}\tfirst_instruction_node={}\tbyte={}",
            divergence.left,
            divergence.right,
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
            divergence.first_different_byte
        ));
        if verify_plan.print_bisection_state_dump {
            outcome.stdout.push(format!(
                "verify-bisect-state\tleft_state={}\tright_state={}\tleft_dump={}\tright_dump={}",
                divergence.left_state_digest,
                divergence.right_state_digest,
                divergence.left_state_dump,
                divergence.right_state_dump
            ));
        }
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: divergence
                .first_different_virtual_time_node
                .clone()
                .or_else(|| divergence.first_different_instruction_node.clone())
                .unwrap_or_else(|| String::from("verify")),
            kind: String::from("verify_divergence_bisection"),
            summary: format!(
                "left={} right={} mismatch={} first_virtual_time={} first_virtual_time_node={} first_instruction={} first_instruction_node={} byte={}",
                divergence.left,
                divergence.right,
                divergence.mismatch.label(),
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
                divergence.first_different_byte
            ),
        });
        let left = report
            .witnesses
            .get(divergence.left)
            .ok_or_else(|| backend_error("verify divergence left side is out of range"))?;
        let right = report
            .witnesses
            .get(divergence.right)
            .ok_or_else(|| backend_error("verify divergence right side is out of range"))?;
        if let (Some(left_artifact), Some(right_artifact)) =
            (left.artifact.as_ref(), right.artifact.as_ref())
        {
            outcome.side_reproduction_artifacts = vec![
                (String::from("left"), left_artifact.clone()),
                (String::from("right"), right_artifact.clone()),
            ];
            let mut artifact_material = Vec::new();
            artifact_material.extend_from_slice(left_artifact);
            artifact_material.extend_from_slice(right_artifact);
            outcome.artifact_digest = content_address_bytes(&artifact_material);
        } else {
            outcome.stdout.push(String::from(
                "verify-reproduction-artifacts\tskipped=producer-provenance-unavailable",
            ));
        }
    } else {
        outcome.stdout.push(format!(
            "verify-result\tstatus=passed\treductions={}\tcanonical_log={}\tfingerprint={}",
            report.witnesses.len(),
            report
                .witnesses
                .first()
                .map(|witness| content_address_bytes(&witness.canonical_log_bytes))
                .unwrap_or_else(|| content_address_bytes(b"verify-empty-log")),
            report
                .witnesses
                .first()
                .map(|witness| content_address_bytes(&witness.fingerprint_stream))
                .unwrap_or_else(|| content_address_bytes(b"verify-empty-fingerprint"))
        ));
    }
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
    Ok(outcome)
}
