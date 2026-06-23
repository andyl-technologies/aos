//! Checks `gate:layer0-determinism` for the L0 simulation crate.

#![forbid(unsafe_code)]

use crucible_sim::contract_a::{
    ContractAConfig, ContractADriver, HashingContractAVm, RecordedInput, TimeTrajectorySample,
};
use crucible_sim::{DecisionRng, StableDigest, StableHasher, stable_name_hash};

#[test]
fn gate_layer0_determinism_reduces_fixed_contract_a_twice() {
    let config = contract_a_config("console=ttyS0 nokaslr norandmaps", 0x0010_c001);
    let inputs = vec![
        RecordedInput::new(0, b"boot".to_vec()),
        RecordedInput::new(3, b"deterministic-io".to_vec()),
        RecordedInput::new(7, b"timer".to_vec()),
    ];

    let fingerprint =
        assert_twice_reduce_canonical_digest(|| run_contract_a(&config, &inputs, 12).fingerprint);
    let first = run_contract_a(&config, &inputs, 12);

    assert_eq!(first.fingerprint, fingerprint);
    assert_eq!(first.instruction_stream.len(), 12);
    assert_eq!(first.architectural_state_trajectory.len(), 12);
    assert_eq!(first.time_trajectory.len(), 12);
    assert_eq!(
        first.time_trajectory.last(),
        Some(&TimeTrajectorySample {
            aggregate_icount: 12,
            virtual_time_ns: 12,
        })
    );
    assert_eq!(first.time_fingerprint.final_icount, 12);
    assert_eq!(first.time_fingerprint.final_virtual_time_ns, 12);
    assert_eq!(
        first
            .instruction_stream
            .last()
            .map(|sample| sample.aggregate_icount),
        Some(12)
    );
}

#[test]
fn gate_layer0_determinism_is_sensitive_to_each_fixed_input() {
    let base = contract_a_config("console=ttyS0 nokaslr norandmaps", 0x0010_c001);
    let seed_changed = contract_a_config("console=ttyS0 nokaslr norandmaps", 0x0010_c002);
    let cmdline_changed = contract_a_config("console=ttyS0 quiet nokaslr norandmaps", 0x0010_c001);
    let inputs = vec![RecordedInput::new(4, b"payload-a".to_vec())];
    let payload_changed = vec![RecordedInput::new(4, b"payload-b".to_vec())];

    let baseline = run_contract_a(&base, &inputs, 10).fingerprint;

    assert_ne!(
        baseline,
        run_contract_a(&seed_changed, &inputs, 10).fingerprint
    );
    assert_ne!(
        baseline,
        run_contract_a(&cmdline_changed, &inputs, 10).fingerprint
    );
    assert_ne!(
        baseline,
        run_contract_a(&base, &payload_changed, 10).fingerprint
    );
    assert_ne!(baseline, run_contract_a(&base, &inputs, 11).fingerprint);
}

#[test]
fn gate_layer0_determinism_keeps_named_streams_stable_under_entity_addition() {
    let before = named_decision("node-a", 0, 0x0010_c001);
    let added_entity = named_decision("node-b", 0, 0x0010_c001);
    let after = named_decision("node-a", 0, 0x0010_c001);

    assert_eq!(before, after);
    assert_ne!(before, added_entity);
    assert_eq!(
        DecisionRng::new(0x0010_c001).stream_seed("node-a"),
        0x0010_c001 ^ stable_name_hash("node-a")
    );
}

#[test]
fn gate_layer0_determinism_rejects_unordered_recorded_inputs() {
    let config = contract_a_config("console=ttyS0 nokaslr norandmaps", 0x0010_c001);
    let inputs = vec![
        RecordedInput::new(5, b"later".to_vec()),
        RecordedInput::new(4, b"earlier".to_vec()),
    ];
    let mut vm = HashingContractAVm::default();

    let result = ContractADriver::run(&mut vm, &config, &inputs, 8);

    assert!(result.is_err());
}

fn assert_twice_reduce_canonical_digest<D, F>(mut reduce: F) -> D
where
    D: Clone + std::fmt::Debug + PartialEq,
    F: FnMut() -> D,
{
    let first = reduce();
    let second = reduce();

    assert_eq!(first, second);

    first
}

fn contract_a_config(cmdline: &str, seed: u64) -> ContractAConfig {
    match ContractAConfig::new(image_digest(), cmdline, seed, 2, 4) {
        Ok(config) => config,
        Err(error) => panic!("gate Contract A config should be valid: {error}"),
    }
}

fn run_contract_a(
    config: &ContractAConfig,
    inputs: &[RecordedInput],
    retired_instruction_count: u64,
) -> crucible_sim::contract_a::ContractARun {
    let mut vm = HashingContractAVm::default();
    match ContractADriver::run(&mut vm, config, inputs, retired_instruction_count) {
        Ok(run) => run,
        Err(error) => panic!("gate Contract A run should be valid: {error}"),
    }
}

fn named_decision(entity: &str, request_id: u64, root_seed: u64) -> u64 {
    let mut stream = DecisionRng::new(root_seed).fork(entity);
    let mut draw = 0;
    for _ in 0..=request_id {
        draw = stream.next_u64();
    }
    draw
}

fn image_digest() -> StableDigest {
    let mut hasher = StableHasher::new();
    hasher.write_tag("layer0-gate-image");
    hasher.finish()
}
