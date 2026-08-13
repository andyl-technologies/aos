//! Packaged-QEMU artifact replay planning and branch reconstruction.

use super::*;

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
        let error = match replay_branch_evidence(&scenario, base, 2) {
            Ok(_) => panic!("unrecorded branch frontier must fail closed"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("exceeded the latest recorded"));
        Ok(())
    }
}
