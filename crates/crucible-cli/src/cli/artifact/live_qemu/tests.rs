//! Live-QEMU replay-contract codec and validation tests.

use super::*;

fn fork_contract() -> LiveQemuReplayContract {
    LiveQemuReplayContract {
        producer: String::from("fork"),
        terminal_condition: String::from("quiescence"),
        terminal_status: String::from("failed"),
        terminal_outcome: String::from("failed"),
        terminal_configuration: String::from("blake3:terminal"),
        final_frontier_ticks: 42,
        final_quanta: 7,
        budget_timed_out: false,
        max_virtual_time_ticks: None,
        max_quanta: Some(8),
        run_ceiling_icount: Some(12),
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
                command: String::from("fork"),
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
    }
}

fn producer_contract(producer: &str) -> LiveQemuReplayContract {
    let mut contract = fork_contract();
    contract.producer = producer.to_string();
    match producer {
        "search" => {
            contract.branch = LiveQemuReplayBranch::None;
            contract.network_choice_indices = vec![2, 5];
            contract.startup_controls.clear();
        }
        "fork" => {}
        _ => {
            contract.branch = LiveQemuReplayBranch::None;
            contract.fingerprint_scope = LiveQemuFingerprintScope::FullExecution;
            contract.network_choice_indices = vec![2, 5];
            contract.startup_controls[0].command = String::from("start");
        }
    }
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
    let contract = fork_contract();
    let encoded = contract.encode();
    assert_eq!(LiveQemuReplayContract::decode(&encoded)?, contract);
    Ok(())
}

#[test]
fn live_qemu_replay_contract_accepts_every_closed_producer() -> Result<(), CliError> {
    for producer in ["run", "verify", "search", "fuzz", "fork"] {
        let contract = producer_contract(producer);
        assert_eq!(
            LiveQemuReplayContract::decode(&contract.encode())?,
            contract
        );
    }
    Ok(())
}

#[test]
fn live_qemu_replay_contract_restricts_fork_startup_to_fork_producers() {
    let mut contract = fork_contract();
    contract.producer = String::from("run");
    contract.branch = LiveQemuReplayBranch::None;
    contract.fingerprint_scope = LiveQemuFingerprintScope::FullExecution;

    let error = rejected_contract(
        &contract,
        "non-fork producer must reject a fork startup control",
    );
    assert!(error.to_string().contains("unsupported startup control"));
}

#[test]
fn live_qemu_replay_contract_requires_exact_fork_control_shape() {
    for startup in [
        vec!["fork"],
        vec!["continue", "fork"],
        vec!["fork", "fork", "continue"],
        vec!["start", "fork", "continue"],
    ] {
        let mut contract = fork_contract();
        contract.startup_controls = startup
            .into_iter()
            .enumerate()
            .map(|(sequence, command)| LiveQemuReplayControl {
                sequence: sequence as u64,
                command: command.to_string(),
            })
            .collect();
        let error = rejected_contract(&contract, "invalid fork startup shape must fail");
        assert!(error.to_string().contains("fork replay requires"));
    }

    let mut missing_query = fork_contract();
    missing_query.initial_controls.clear();
    let error = rejected_contract(&missing_query, "fork initial query is mandatory");
    assert!(error.to_string().contains("fork replay requires"));
}

#[test]
fn live_qemu_replay_contract_round_trips_unmodified_fork_resume() -> Result<(), CliError> {
    let mut contract = fork_contract();
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
    let mut contract = fork_contract();
    contract.producer = String::from("unknown");
    let error = rejected_contract(&contract, "unsupported producer must fail closed");
    assert!(error.to_string().contains("unsupported producer"));
}

#[test]
fn live_qemu_replay_contract_rejects_duplicate_choice_indices() {
    let mut contract = fork_contract();
    contract.network_choice_indices = vec![4, 4];
    let error = rejected_contract(&contract, "duplicate choice indices must fail closed");
    assert!(error.to_string().contains("unique and increasing"));
}

#[test]
fn live_qemu_replay_contract_rejects_pre_branch_choices() {
    let mut contract = fork_contract();
    contract.network_choice_indices = vec![2, 4];
    let error = rejected_contract(
        &contract,
        "pre-branch choices must remain owned by the retained base",
    );
    assert!(error.to_string().contains("post-branch suffix"));
}

#[test]
fn live_qemu_replay_contract_rejects_incompatible_fingerprint_scope() {
    let mut contract = producer_contract("search");
    contract.fingerprint_scope = LiveQemuFingerprintScope::FullExecution;
    let error = rejected_contract(
        &contract,
        "search artifacts must declare their terminal snapshot scope",
    );
    assert!(error.to_string().contains("fingerprint scope"));
}

#[test]
fn live_qemu_replay_contract_rejects_missing_fork_branch() {
    let mut contract = fork_contract();
    contract.branch = LiveQemuReplayBranch::None;
    let error = rejected_contract(&contract, "fork without a retained base must fail closed");
    assert!(error.to_string().contains("branch recipes"));
}

#[test]
fn live_qemu_replay_contract_rejects_unknown_control_commands() {
    let mut contract = fork_contract();
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
    let mut contract = fork_contract();
    contract.startup_controls[0].command = String::from("pause");
    let error = rejected_contract(&contract, "payload-free startup recipes must remain closed");
    assert!(error.to_string().contains("unsupported startup control"));
}

#[test]
fn live_qemu_replay_contract_rejects_noncontiguous_initial_controls() {
    let mut contract = fork_contract();
    contract.initial_controls[0].sequence = 1;
    let error = rejected_contract(
        &contract,
        "initial controls must preserve their exact order",
    );
    assert!(error.to_string().contains("contiguous from zero"));
}
