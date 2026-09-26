//! Live-QEMU replay-contract codec and validation tests.

use super::*;

fn campaign_branch_contract() -> LiveQemuReplayContract {
    let scenario = crucible::happy_path_scenario()
        .unwrap_or_else(|error| panic!("build live-QEMU contract scenario: {error}"))
        .scenario;
    let initial = crucible::Configuration::genesis(scenario.scenario_def());

    LiveQemuReplayContract {
        producer: String::from("campaign-run"),
        execution_owner: RunExecutionOwner::Campaign,
        execution_mode: RunExecutionMode::ToCompletion,
        initial_configuration: format_content_hash_ref(initial.id()),
        initial_scenario: scenario.to_compact_binary(),
        initial_schedule: crucible::Schedule::empty().to_compact_binary(),
        terminal_condition: String::from("quiescence"),
        terminal_status: String::from("failed"),
        terminal_outcome: String::from("failed"),
        terminal_configuration: String::from("blake3:terminal"),
        final_frontier_ticks: 42,
        final_quanta: 7,
        final_event_log_len: 0,
        final_schedule: crucible::Schedule::empty().to_compact_binary(),
        terminal_savepoint: None,
        budget_timed_out: false,
        max_virtual_time_ticks: None,
        max_quanta: Some(8),
        run_ceiling_ticks: Some(12),
        lifecycle_quantum_budget: Some(16),
        coverage: true,
        fingerprint_scope: LiveQemuFingerprintScope::TerminalAllNodes,
        branch: LiveQemuReplayBranch::Reseed {
            base_decisions: 3,
            frontier_ticks: 11,
            seed: 99,
        },
        network_choice_indices: vec![5],
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
        controls: vec![
            LiveQemuReplayControl {
                sequence: 0,
                command: String::from("start"),
            },
            LiveQemuReplayControl {
                sequence: 1,
                command: String::from("continue"),
            },
        ],
        reproduction_commands: Vec::new(),
    }
}

fn producer_contract(producer: &str) -> LiveQemuReplayContract {
    let mut contract = campaign_branch_contract();
    contract.producer = producer.to_string();
    match producer {
        "campaign-search" => {
            contract.branch = LiveQemuReplayBranch::None;
            contract.network_choice_indices = vec![2, 5];
            contract.startup_controls.clear();
        }
        "campaign-run" => {}
        _ => {
            contract.branch = LiveQemuReplayBranch::None;
            contract.fingerprint_scope = LiveQemuFingerprintScope::FullExecution;
            contract.network_choice_indices = vec![2, 5];
            contract.startup_controls[0].command = String::from("start");
        }
    }
    contract
}

fn interactive_contract() -> LiveQemuReplayContract {
    let mut contract = producer_contract("run");
    contract.execution_owner = RunExecutionOwner::Session;
    contract.execution_mode = RunExecutionMode::Interactive;
    contract.terminal_condition = String::from("interactive-stop");
    contract.terminal_status = String::from("passed");
    contract.terminal_outcome = String::from("stopped");
    contract.fingerprint_scope = LiveQemuFingerprintScope::TerminalAllNodes;
    contract.reproduction_commands = vec![crucible_api::ReproductionCommandRecord {
        sequence: 1,
        payload: crucible_api::ReproductionCommandPayload {
            command: SessionCommandKind::Stop,
            command_payload: String::from("payload=command-kind\ncommand=Stop\n"),
            scheduler_batch: 0,
            scheduler_control: None,
        },
        virtual_time: crucible::VirtualTime { ticks: 42 },
        quanta: 7,
        at_sequence: 11,
        result: crucible_api::ReproductionCommandResult::Accepted,
        observational_order: 1,
    }];
    contract
}

fn rejected_contract(contract: &LiveQemuReplayContract, reason: &str) -> CliError {
    match LiveQemuReplayContract::decode(&contract.encode()) {
        Err(error) => error,
        Ok(_) => panic!("{reason}"),
    }
}

#[test]
fn live_qemu_replay_contract_round_trips_canonically() -> Result<(), CliError> {
    let contract = campaign_branch_contract();
    let encoded = contract.encode();
    assert_eq!(LiveQemuReplayContract::decode(&encoded)?, contract);
    Ok(())
}

#[test]
fn interactive_live_qemu_contract_round_trips_full_control_records() -> Result<(), CliError> {
    let contract = interactive_contract();
    let encoded = contract.encode();
    assert_eq!(LiveQemuReplayContract::decode(&encoded)?, contract);
    Ok(())
}

#[test]
fn live_qemu_contract_rejects_an_unsupported_schema() {
    let encoded = interactive_contract().encode();
    let unsupported = String::from_utf8(encoded)
        .unwrap_or_else(|error| panic!("contract fixture should be UTF-8: {error}"))
        .replacen(
            "crucible.live-qemu-replay-contract.v5",
            "crucible.live-qemu-replay-contract.v4",
            1,
        );
    let error = match LiveQemuReplayContract::decode(unsupported.as_bytes()) {
        Err(error) => error,
        Ok(_) => panic!("an unsupported live contract schema must fail closed"),
    };
    assert!(error.to_string().contains("unsupported"));
}

#[test]
fn live_qemu_contract_rejects_initial_scenario_identity_mismatch() {
    let mut contract = interactive_contract();
    contract.initial_configuration = String::from("blake3:wrong-initial-configuration");
    let error = rejected_contract(
        &contract,
        "initial scenario and schedule must authenticate their configuration",
    );
    assert!(error.to_string().contains("initial configuration identity"));
}

#[test]
fn interactive_live_qemu_contract_rejects_corrupt_record_payload() {
    let mut contract = interactive_contract();
    contract.reproduction_commands[0].payload.command_payload =
        String::from("payload=command-kind\ncommand=Pause\n");
    let error = rejected_contract(&contract, "mismatched command payload must fail closed");
    assert!(
        error
            .to_string()
            .contains("invalid reproduction command record")
    );
}

#[test]
fn live_qemu_replay_contract_accepts_every_closed_producer() -> Result<(), CliError> {
    for producer in [
        "campaign-run",
        "campaign-search",
        "verify",
        "search",
        "fuzz",
    ] {
        let contract = producer_contract(producer);
        assert_eq!(
            LiveQemuReplayContract::decode(&contract.encode())?,
            contract
        );
    }
    Ok(())
}

#[test]
fn live_qemu_replay_contract_requires_exact_branch_control_shape() {
    for startup in [
        vec!["start"],
        vec!["continue", "start"],
        vec!["start", "start", "continue"],
        vec!["continue", "start", "continue"],
    ] {
        let mut contract = campaign_branch_contract();
        contract.startup_controls = startup
            .into_iter()
            .enumerate()
            .map(|(sequence, command)| LiveQemuReplayControl {
                sequence: sequence as u64,
                command: command.to_string(),
            })
            .collect();
        let error = rejected_contract(&contract, "invalid branch startup shape must fail");
        assert!(error.to_string().contains("branch replay requires"));
    }

    let mut missing_query = campaign_branch_contract();
    missing_query.initial_controls.clear();
    let error = rejected_contract(&missing_query, "branch initial query is mandatory");
    assert!(error.to_string().contains("branch replay requires"));
}

#[test]
fn live_qemu_replay_contract_round_trips_campaign_resume() -> Result<(), CliError> {
    let mut contract = campaign_branch_contract();
    contract.branch = LiveQemuReplayBranch::Resume {
        base_decisions: 3,
        frontier_ticks: 11,
    };
    assert_eq!(
        LiveQemuReplayContract::decode(&contract.encode())?,
        contract
    );
    Ok(())
}

#[test]
fn live_qemu_replay_contract_rejects_unsupported_producer() {
    let mut contract = campaign_branch_contract();
    contract.producer = String::from("unknown");
    let error = rejected_contract(&contract, "unsupported producer must fail closed");
    assert!(error.to_string().contains("unsupported producer"));
}

#[test]
fn live_qemu_replay_contract_rejects_duplicate_choice_indices() {
    let mut contract = campaign_branch_contract();
    contract.network_choice_indices = vec![4, 4];
    let error = rejected_contract(&contract, "duplicate choice indices must fail closed");
    assert!(error.to_string().contains("unique and increasing"));
}

#[test]
fn live_qemu_replay_contract_rejects_pre_branch_choices() {
    let mut contract = campaign_branch_contract();
    contract.network_choice_indices = vec![2, 4];
    let error = rejected_contract(
        &contract,
        "pre-branch choices must remain owned by the retained base",
    );
    assert!(error.to_string().contains("post-branch suffix"));
}

#[test]
fn live_qemu_replay_contract_rejects_incompatible_fingerprint_scope() {
    let mut contract = producer_contract("campaign-search");
    contract.fingerprint_scope = LiveQemuFingerprintScope::FullExecution;
    let error = rejected_contract(
        &contract,
        "search artifacts must declare their terminal snapshot scope",
    );
    assert!(error.to_string().contains("fingerprint scope"));
}

#[test]
fn live_qemu_replay_contract_rejects_unknown_control_commands() {
    let mut contract = campaign_branch_contract();
    contract.controls[0].command = String::from("unknown");
    let error = rejected_contract(&contract, "unknown control commands must fail closed");
    assert!(
        error
            .to_string()
            .contains("unsupported acknowledged control command")
    );
}

#[test]
fn live_qemu_replay_contract_rejects_unsupported_startup_controls() {
    let mut contract = campaign_branch_contract();
    contract.startup_controls[0].command = String::from("pause");
    let error = rejected_contract(&contract, "payload-free startup recipes must remain closed");
    assert!(error.to_string().contains("unsupported startup control"));
}

#[test]
fn live_qemu_replay_contract_rejects_noncontiguous_initial_controls() {
    let mut contract = campaign_branch_contract();
    contract.initial_controls[0].sequence = 1;
    let error = rejected_contract(
        &contract,
        "initial controls must preserve their exact order",
    );
    assert!(error.to_string().contains("contiguous from zero"));
}
