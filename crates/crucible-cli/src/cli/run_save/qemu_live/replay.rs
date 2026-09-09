//! Packaged-QEMU artifact replay planning and branch reconstruction.

use super::*;

/// Optional authenticated resources carried by a live-QEMU replay artifact.
pub(crate) struct LiveQemuReplayResources {
    pub(crate) campaign_closure:
        Option<crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignReplayClosure>,
    pub(crate) effect_trace: Option<crucible::ResolvedEffectTrace>,
    pub(crate) lifecycle_artifacts: Option<std::sync::Arc<crucible::MemoryDagStore>>,
    pub(crate) bounded_scheduler_preemption:
        Option<crucible_api::BoundedSchedulerPreemptionEvidence>,
}

/// Re-executes a v3 artifact through a fresh packaged-QEMU lifecycle session.
///
/// # Errors
///
/// Returns [`CliError`] when the contract is invalid, its branch recipe cannot
/// be reconstructed from the typed schedule, or the QEMU lifecycle fails.
pub(crate) fn run_live_qemu_artifact_replay(
    backend: &ResolvedLocalBackend,
    campaign_deployment: Option<&Path>,
    scenario: crucible::ScenarioDefForm,
    schedule: &crucible::Schedule,
    contract: &LiveQemuReplayContract,
    resources: LiveQemuReplayResources,
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
        campaign_deployment: campaign_deployment.map(Path::to_path_buf),
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
    if let Some(lifecycle_artifacts) = resources.lifecycle_artifacts {
        config = config
            .with_world_artifacts(lifecycle_artifacts.clone())
            .with_signal_artifacts(lifecycle_artifacts);
    }
    if let Some(evidence) = resources.bounded_scheduler_preemption {
        config = config.with_bounded_scheduler_preemption(evidence);
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
    let network_choices =
        replay_indexed_network_choices(schedule, &contract.network_choice_indices)?;
    if !network_choices.is_empty() {
        config = config.with_branch_network_choices(network_choices);
    }
    if contract.coverage {
        config = config.with_coverage(production_api::ProductionPluginSwitch::On);
    }
    if let Some(trace) = resources.effect_trace {
        config = config.with_fault_replay(trace);
    }
    let execution_owner = expected_live_qemu_execution_owner(contract, schedule);
    let report = if matches!(execution_owner, RunExecutionOwner::Campaign) {
        let replay_closure = campaign_owner_replay_closure(
            &contract.producer,
            schedule,
            resources.campaign_closure,
        )?;
        crate::cli_verify_serve::run_local_qemu_campaign_replay(
            backend,
            &run_plan,
            config,
            schedule.clone(),
            replay_closure,
        )?
    } else {
        if resources.campaign_closure.is_some() {
            return Err(artifact_error(
                "session-owned replay cannot consume a campaign replay closure",
            ));
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let control_plane =
            production_qemu_control_plane(config, &scenario).with_thin_replay_resume();
        let client = InProcessLifecycleClient::new(control_plane);
        if contract.producer == "fork" {
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
                        replay_has_exact_branch_choices(&contract.network_choice_indices),
                    ),
                )?
                .run
        } else {
            runtime.block_on(run_control_client_workflow_with_interactive_driver(
                &client,
                &run_plan,
                InteractiveCommandDriver::Preparsed(&[]),
                false,
                replay_has_exact_branch_choices(&contract.network_choice_indices),
            ))?
        }
    };
    Ok((run_plan, report))
}

pub(crate) fn expected_live_qemu_execution_owner(
    contract: &LiveQemuReplayContract,
    schedule: &crucible::Schedule,
) -> RunExecutionOwner {
    if contract.producer == "campaign-run"
        || (contract.producer == "run" && legacy_run_campaign_replay_eligible(contract, schedule))
    {
        RunExecutionOwner::Campaign
    } else {
        RunExecutionOwner::Session
    }
}

fn legacy_run_campaign_replay_eligible(
    contract: &LiveQemuReplayContract,
    schedule: &crucible::Schedule,
) -> bool {
    let standard_startup =
        replay_control_commands(&contract.startup_controls) == ["start", "continue"];
    let standard_initial = replay_control_commands(&contract.initial_controls) == ["query"];
    let unattended_controls = contract.controls.iter().all(|control| {
        matches!(
            control.command.as_str(),
            "query" | "continue" | "step-quantum" | "stop"
        )
    });
    let supported_terminal = matches!(
        contract.terminal_condition.as_str(),
        "quiescence" | "virtual-time" | "stopped"
    ) && (contract.terminal_condition != "virtual-time"
        || contract.max_virtual_time_ticks.is_some());
    let supported_schedule = schedule.decisions().iter().all(|decision| {
        matches!(
            decision,
            crucible::Decision::DeliveryOrder(_)
                | crucible::Decision::RngDraw(_)
                | crucible::Decision::Preemption(_)
        )
    });

    standard_startup
        && standard_initial
        && unattended_controls
        && supported_terminal
        && !contract.coverage
        && contract.fingerprint_scope == LiveQemuFingerprintScope::FullExecution
        && matches!(contract.branch, LiveQemuReplayBranch::None)
        && supported_schedule
}

fn replay_control_commands(controls: &[LiveQemuReplayControl]) -> Vec<&str> {
    controls
        .iter()
        .map(|control| control.command.as_str())
        .collect()
}

fn campaign_owner_replay_closure(
    producer: &str,
    schedule: &crucible::Schedule,
    embedded: Option<crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignReplayClosure>,
) -> Result<crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignReplayClosure, CliError> {
    match (producer, embedded) {
        ("campaign-run", Some(closure)) => Ok(closure),
        ("campaign-run", None) => Err(artifact_error(
            "campaign-run replay requires its authenticated choice closure",
        )),
        ("run", None) => {
            crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignReplayClosure::empty_for_selection_free_schedule(schedule)
                .map_err(|error| artifact_error(format!("build legacy run replay closure: {error}")))
        }
        ("run", Some(_)) => Err(artifact_error(
            "legacy run replay cannot carry a campaign replay closure",
        )),
        (_, _) => Err(artifact_error(
            "only campaign-run and eligible legacy run artifacts use campaign replay",
        )),
    }
}

fn replay_has_exact_branch_choices(network_indices: &[u64]) -> bool {
    !network_indices.is_empty()
}

fn replay_branch_evidence(
    scenario_form: &crucible::ScenarioDefForm,
    configuration: crucible::Configuration,
    frontier_ticks: u64,
) -> Result<ResumeHandleEvidence, CliError> {
    let frontier = validate_resume_handle_frontier(&configuration.schedule, frontier_ticks)?;
    let checkpoint = checkpoint_for_resume_configuration(&configuration, frontier)?;
    let replay_closure = authenticated_replay_closure(
        scenario_form,
        &configuration.schedule,
        None,
        "session-owned replay branch",
    )?;
    Ok(ResumeHandleEvidence {
        scenario_form: scenario_form.clone(),
        scenario: scenario_form.scenario_def(),
        schedule: configuration.schedule.clone(),
        configuration,
        checkpoint,
        replay_closure,
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

    fn legacy_run_contract() -> LiveQemuReplayContract {
        LiveQemuReplayContract {
            producer: String::from("run"),
            terminal_condition: String::from("quiescence"),
            terminal_status: String::from("failed"),
            terminal_outcome: String::from("failed"),
            terminal_configuration: String::from("blake3:terminal"),
            final_frontier_ticks: 1,
            final_quanta: 1,
            budget_timed_out: false,
            max_virtual_time_ticks: None,
            max_quanta: None,
            run_ceiling_icount: Some(PRODUCTION_CLI_RUN_CEILING_ICOUNT),
            lifecycle_quantum_budget: Some(PRODUCTION_CLI_QUANTUM_BUDGET),
            coverage: false,
            fingerprint_scope: LiveQemuFingerprintScope::FullExecution,
            branch: LiveQemuReplayBranch::None,
            network_choice_indices: Vec::new(),
            startup_controls: vec![
                LiveQemuReplayControl {
                    sequence: 0,
                    command: String::from("start"),
                },
                LiveQemuReplayControl {
                    sequence: 1,
                    command: String::from("continue"),
                },
            ],
            initial_controls: vec![LiveQemuReplayControl {
                sequence: 0,
                command: String::from("query"),
            }],
            controls: Vec::new(),
        }
    }

    #[test]
    fn replay_requires_an_exact_network_choice_stream_when_branching() {
        assert!(!replay_has_exact_branch_choices(&[]));
        assert!(replay_has_exact_branch_choices(&[5]));
    }

    #[test]
    fn campaign_and_supported_legacy_run_artifacts_route_to_the_campaign_owner() {
        let supported = Schedule::from_decisions([crucible::Decision::DeliveryOrder(
            crucible::DeliveryOrderDecision {
                at: VirtualTime { ticks: 1 },
                order: Vec::new(),
            },
        )]);
        let legacy_run = legacy_run_contract();
        let mut campaign_run = legacy_run.clone();
        campaign_run.producer = String::from("campaign-run");
        assert_eq!(
            expected_live_qemu_execution_owner(&campaign_run, &supported),
            RunExecutionOwner::Campaign
        );
        assert_eq!(
            expected_live_qemu_execution_owner(&legacy_run, &supported),
            RunExecutionOwner::Campaign,
        );
        let synthesized = match campaign_owner_replay_closure("run", &supported, None) {
            Ok(closure) => closure,
            Err(error) => panic!("supported legacy run should synthesize a closure: {error}"),
        };
        let encoded = match synthesized.to_canonical_bytes() {
            Ok(encoded) => encoded,
            Err(error) => panic!("empty legacy replay closure should encode: {error}"),
        };
        assert_eq!(encoded, b"CCRC\0\0\0\x01\0\0\0\0");
        for producer in ["verify", "search", "fuzz", "fork"] {
            let mut contract = legacy_run.clone();
            contract.producer = producer.to_string();
            assert_eq!(
                expected_live_qemu_execution_owner(&contract, &supported),
                RunExecutionOwner::Session,
                "legacy producer {producer} must retain session replay semantics",
            );
        }
    }

    #[test]
    fn campaign_run_replay_still_requires_its_embedded_closure() {
        let error = match campaign_owner_replay_closure("campaign-run", &Schedule::empty(), None) {
            Ok(_) => panic!("campaign-run replay without its closure must fail closed"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("requires its authenticated choice closure")
        );
    }

    #[test]
    fn legacy_run_override_replay_retains_the_compatible_session_owner() {
        let contract = legacy_run_contract();
        let unsupported =
            Schedule::from_decisions([crucible::Decision::Override(crucible::OverrideDecision {
                point: crucible::SchedulingPoint {
                    key: String::from("legacy-run/choice"),
                },
                choice: crucible::ChoiceTag {
                    name: String::from("alternate"),
                },
            })]);

        assert_eq!(
            expected_live_qemu_execution_owner(&contract, &unsupported),
            RunExecutionOwner::Session,
            "an uncovered legacy override cannot enter fresh campaign replay",
        );
    }

    #[test]
    fn legacy_run_session_control_and_property_contracts_retain_the_session_owner() {
        let schedule = Schedule::empty();

        let mut property = legacy_run_contract();
        property.terminal_condition = String::from("property");
        assert_eq!(
            expected_live_qemu_execution_owner(&property, &schedule),
            RunExecutionOwner::Session,
        );

        let mut interactive = legacy_run_contract();
        interactive.startup_controls.pop();
        interactive.controls.push(LiveQemuReplayControl {
            sequence: 0,
            command: String::from("pause"),
        });
        assert_eq!(
            expected_live_qemu_execution_owner(&interactive, &schedule),
            RunExecutionOwner::Session,
        );

        let mut coverage = legacy_run_contract();
        coverage.coverage = true;
        assert_eq!(
            expected_live_qemu_execution_owner(&coverage, &schedule),
            RunExecutionOwner::Session,
        );
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
