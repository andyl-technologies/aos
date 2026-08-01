//! Checks the isolated Contract A single-VM driver.

#![forbid(unsafe_code)]

use crucible_sim::contract_a::{
    ContractAConfig, ContractAConfigError, ContractADriver, ContractAError,
    ContractAExecutionError, ContractARun, ContractAVm, HashingContractAVm,
    MAX_CONTRACT_A_ICOUNT_SHIFT, MAX_CONTRACT_A_RETIRED_INSTRUCTIONS, MAX_CONTRACT_A_VCPU_COUNT,
    RecordedInput, RetireRequest, TimeTrajectorySample, VcpuRegisterFileRequest,
};
use crucible_sim::{StableDigest, StableHasher};

fn image_digest() -> StableDigest {
    let mut hasher = StableHasher::new();
    hasher.write_tag("test-image");
    hasher.finish()
}

fn digest_from_events(tag: &str, events: &[String]) -> StableDigest {
    let mut hasher = StableHasher::new();
    hasher.write_tag(tag);
    for event in events {
        hasher.write_bytes(event.as_bytes());
    }
    hasher.finish()
}

fn config() -> ContractAConfig {
    match ContractAConfig::new(image_digest(), "console=ttyS0 nokaslr", 7, 1, 4) {
        Ok(config) => config,
        Err(error) => panic!("test Contract A config should be valid: {error}"),
    }
}

fn run_hashing(
    config: &ContractAConfig,
    inputs: &[RecordedInput],
    retired_instruction_count: u64,
) -> ContractARun {
    let mut vm = HashingContractAVm::default();
    match ContractADriver::run(&mut vm, config, inputs, retired_instruction_count) {
        Ok(run) => run,
        Err(error) => panic!("test Contract A run should be valid: {error}"),
    }
}

#[derive(Clone, Copy)]
enum AdversarialHostProfile {
    FastHostManyCores,
    LoadedHostSingleCore,
    ReorderedHostScheduling,
}

impl AdversarialHostProfile {
    fn apply_host_noise(self, sink: &mut StableHasher) {
        match self {
            Self::FastHostManyCores => {
                sink.write_tag("fast-host-many-cores");
                sink.write_u64(64);
            }
            Self::LoadedHostSingleCore => {
                sink.write_tag("loaded-host-single-core");
                sink.write_u64(1);
                sink.write_u64(10_000);
            }
            Self::ReorderedHostScheduling => {
                sink.write_tag("reordered-host-scheduling");
                for token in [3_u64, 1, 4, 1, 5, 9] {
                    sink.write_u64(token);
                }
            }
        }
    }
}

#[derive(Default)]
struct RecordingVm {
    events: Vec<String>,
}

struct PerturbingRegisterVm {
    inner: HashingContractAVm,
    perturbed_vcpu: u64,
}

impl PerturbingRegisterVm {
    fn new(perturbed_vcpu: u64) -> Self {
        Self {
            inner: HashingContractAVm::default(),
            perturbed_vcpu,
        }
    }
}

impl ContractAVm for RecordingVm {
    fn reset(&mut self, config: &ContractAConfig) -> Result<(), ContractAExecutionError> {
        self.events.push(format!("reset:{}", config.seed()));
        Ok(())
    }

    fn inject_recorded_input(
        &mut self,
        input: &RecordedInput,
    ) -> Result<(), ContractAExecutionError> {
        self.events.push(format!(
            "input:{}:{}",
            input.delivery_icount(),
            input.payload().len()
        ));
        Ok(())
    }

    fn retire_instruction(
        &mut self,
        request: RetireRequest,
    ) -> Result<StableDigest, ContractAExecutionError> {
        self.events.push(format!(
            "retire:{}:{}:{}",
            request.aggregate_icount, request.vcpu_id, request.visible_input_count
        ));
        Ok(digest_from_events("recording-vm-instruction", &self.events))
    }

    fn sample_architectural_state(
        &mut self,
        aggregate_icount: u64,
    ) -> Result<StableDigest, ContractAExecutionError> {
        self.events.push(format!("sample:{aggregate_icount}"));
        Ok(digest_from_events("recording-vm-state", &self.events))
    }

    fn sample_vcpu_register_file(
        &mut self,
        request: VcpuRegisterFileRequest,
    ) -> Result<StableDigest, ContractAExecutionError> {
        self.events.push(format!(
            "register:{}:{}:{}:{}",
            request.aggregate_icount,
            request.vcpu_id,
            request.current_vcpu,
            request.vcpu_retired_instruction_count
        ));
        Ok(digest_from_events("recording-vm-registers", &self.events))
    }
}

impl ContractAVm for PerturbingRegisterVm {
    fn reset(&mut self, config: &ContractAConfig) -> Result<(), ContractAExecutionError> {
        self.inner.reset(config)
    }

    fn inject_recorded_input(
        &mut self,
        input: &RecordedInput,
    ) -> Result<(), ContractAExecutionError> {
        self.inner.inject_recorded_input(input)
    }

    fn retire_instruction(
        &mut self,
        request: RetireRequest,
    ) -> Result<StableDigest, ContractAExecutionError> {
        self.inner.retire_instruction(request)
    }

    fn sample_architectural_state(
        &mut self,
        aggregate_icount: u64,
    ) -> Result<StableDigest, ContractAExecutionError> {
        self.inner.sample_architectural_state(aggregate_icount)
    }

    fn sample_vcpu_register_file(
        &mut self,
        request: VcpuRegisterFileRequest,
    ) -> Result<StableDigest, ContractAExecutionError> {
        let base = self.inner.sample_vcpu_register_file(request)?;
        if request.vcpu_id != self.perturbed_vcpu {
            return Ok(base);
        }

        let mut hasher = StableHasher::new();
        hasher.write_tag("perturbed-vcpu-register-file");
        hasher.write_bytes(&base.bytes);
        hasher.write_u64(request.aggregate_icount);
        hasher.write_u64(request.vcpu_id);
        Ok(hasher.finish())
    }
}

#[test]
fn contract_a_driver_feeds_recorded_inputs_into_vm_boundary() {
    let inputs = vec![
        RecordedInput::new(0, b"boot".to_vec()),
        RecordedInput::new(2, b"net".to_vec()),
    ];
    let mut vm = RecordingVm::default();

    let run = match ContractADriver::run(&mut vm, &config(), &inputs, 3) {
        Ok(run) => run,
        Err(error) => panic!("test Contract A run should be valid: {error}"),
    };

    assert_eq!(
        vm.events,
        vec![
            "reset:7",
            "input:0:4",
            "retire:1:0:1",
            "sample:1",
            "register:1:0:0:1",
            "retire:2:0:0",
            "sample:2",
            "register:2:0:0:2",
            "input:2:3",
            "retire:3:0:1",
            "sample:3",
            "register:3:0:0:3",
        ]
    );
    assert_eq!(run.instruction_stream[0].visible_input_count, 1);
    assert_eq!(run.instruction_stream[1].visible_input_count, 0);
    assert_eq!(run.instruction_stream[2].visible_input_count, 1);
}

#[test]
fn contract_a_time_trajectory_is_pure_icount_shift_function() {
    let config =
        match ContractAConfig::new_with_icount_shift(image_digest(), "console=ttyS0", 7, 1, 4, 3) {
            Ok(config) => config,
            Err(error) => panic!("test Contract A config should be valid: {error}"),
        };
    let inputs = vec![
        RecordedInput::new(0, b"boot".to_vec()),
        RecordedInput::new(2, b"net".to_vec()),
    ];

    let run = run_hashing(&config, &inputs, 5);

    assert_eq!(
        run.time_trajectory,
        vec![
            TimeTrajectorySample {
                aggregate_icount: 1,
                virtual_time_ns: 8,
            },
            TimeTrajectorySample {
                aggregate_icount: 2,
                virtual_time_ns: 16,
            },
            TimeTrajectorySample {
                aggregate_icount: 3,
                virtual_time_ns: 24,
            },
            TimeTrajectorySample {
                aggregate_icount: 4,
                virtual_time_ns: 32,
            },
            TimeTrajectorySample {
                aggregate_icount: 5,
                virtual_time_ns: 40,
            },
        ]
    );
    assert_eq!(run.time_fingerprint.icount_shift, 3);
    assert_eq!(run.time_fingerprint.final_icount, 5);
    assert_eq!(run.time_fingerprint.final_virtual_time_ns, 40);
}

#[test]
fn contract_a_time_fingerprint_matches_across_adversarial_host_conditions() {
    let config =
        match ContractAConfig::new_with_icount_shift(image_digest(), "console=ttyS0", 7, 2, 3, 2) {
            Ok(config) => config,
            Err(error) => panic!("test Contract A config should be valid: {error}"),
        };
    let inputs = vec![
        RecordedInput::new(0, b"boot".to_vec()),
        RecordedInput::new(4, b"network".to_vec()),
        RecordedInput::new(7, b"timer".to_vec()),
    ];
    let baseline = run_hashing(&config, &inputs, 9);

    for profile in [
        AdversarialHostProfile::FastHostManyCores,
        AdversarialHostProfile::LoadedHostSingleCore,
        AdversarialHostProfile::ReorderedHostScheduling,
    ] {
        let mut ignored_host_noise = StableHasher::new();
        profile.apply_host_noise(&mut ignored_host_noise);
        let candidate = run_hashing(&config, &inputs, 9);

        assert_eq!(baseline.time_trajectory, candidate.time_trajectory);
        assert_eq!(baseline.time_fingerprint, candidate.time_fingerprint);
        assert_eq!(baseline.fingerprint, candidate.fingerprint);
    }
}

#[test]
fn contract_a_time_fingerprint_ignores_payload_when_icount_horizon_is_fixed() {
    let config =
        match ContractAConfig::new_with_icount_shift(image_digest(), "console=ttyS0", 7, 1, 4, 1) {
            Ok(config) => config,
            Err(error) => panic!("test Contract A config should be valid: {error}"),
        };
    let input_a = vec![RecordedInput::new(2, b"payload-a".to_vec())];
    let input_b = vec![RecordedInput::new(2, b"payload-b".to_vec())];

    let run_a = run_hashing(&config, &input_a, 6);
    let run_b = run_hashing(&config, &input_b, 6);

    assert_eq!(run_a.time_trajectory, run_b.time_trajectory);
    assert_eq!(run_a.time_fingerprint, run_b.time_fingerprint);
    assert_ne!(run_a.fingerprint, run_b.fingerprint);
}

#[test]
fn contract_a_driver_replays_recorded_inputs_identically() {
    let config = config();
    let inputs = vec![
        RecordedInput::new(0, b"boot".to_vec()),
        RecordedInput::new(3, b"net-frame".to_vec()),
        RecordedInput::new(3, b"same-icount-second".to_vec()),
    ];

    let first = run_hashing(&config, &inputs, 8);
    let second = run_hashing(&config, &inputs, 8);

    assert_eq!(first, second);
    assert_eq!(first.instruction_stream.len(), 8);
    assert_eq!(first.architectural_state_trajectory.len(), 8);
    assert_eq!(first.instruction_stream[0].visible_input_count, 1);
    assert_eq!(first.instruction_stream[3].visible_input_count, 2);
}

#[test]
fn contract_a_driver_is_sensitive_to_seed_cmdline_and_input_payload() {
    let base = config();
    let seed_changed = match ContractAConfig::new(image_digest(), "console=ttyS0 nokaslr", 8, 1, 4)
    {
        Ok(config) => config,
        Err(error) => panic!("test Contract A config should be valid: {error}"),
    };
    let cmdline_changed =
        match ContractAConfig::new(image_digest(), "console=ttyS0 quiet nokaslr", 7, 1, 4) {
            Ok(config) => config,
            Err(error) => panic!("test Contract A config should be valid: {error}"),
        };

    let input_a = vec![RecordedInput::new(2, b"payload-a".to_vec())];
    let input_b = vec![RecordedInput::new(2, b"payload-b".to_vec())];

    assert_ne!(
        run_hashing(&base, &input_a, 8).fingerprint,
        run_hashing(&base, &input_b, 8).fingerprint
    );
    assert_ne!(
        run_hashing(&base, &input_a, 8).fingerprint,
        run_hashing(&seed_changed, &input_a, 8).fingerprint
    );
    assert_ne!(
        run_hashing(&base, &input_a, 8).fingerprint,
        run_hashing(&cmdline_changed, &input_a, 8).fingerprint
    );
}

#[test]
fn contract_a_driver_preserves_prefix_before_future_inputs() {
    let config = config();
    let baseline = vec![RecordedInput::new(1, b"early".to_vec())];
    let with_future = vec![
        RecordedInput::new(1, b"early".to_vec()),
        RecordedInput::new(6, b"future".to_vec()),
    ];

    let first = run_hashing(&config, &baseline, 8);
    let second = run_hashing(&config, &with_future, 8);

    assert_eq!(
        &first.instruction_stream[..6],
        &second.instruction_stream[..6]
    );
    assert_eq!(
        &first.architectural_state_trajectory[..6],
        &second.architectural_state_trajectory[..6]
    );
    assert_ne!(first.fingerprint, second.fingerprint);
}

#[test]
fn contract_a_driver_preserves_prefix_when_run_horizon_extends() {
    let config = config();
    let inputs = vec![
        RecordedInput::new(1, b"early".to_vec()),
        RecordedInput::new(4, b"prefix-end".to_vec()),
    ];

    let short = run_hashing(&config, &inputs, 5);
    let long = run_hashing(&config, &inputs, 8);

    assert_eq!(
        short.instruction_stream,
        long.instruction_stream[..short.instruction_stream.len()]
    );
    assert_eq!(
        short.architectural_state_trajectory,
        long.architectural_state_trajectory[..short.architectural_state_trajectory.len()]
    );
}

#[test]
fn contract_a_driver_models_fixed_rr_vcpu_cursor_without_live_peers() {
    let config = match ContractAConfig::new(image_digest(), "console=ttyS0", 11, 3, 2) {
        Ok(config) => config,
        Err(error) => panic!("test Contract A config should be valid: {error}"),
    };

    let run = run_hashing(&config, &[], 7);
    let cursors = run
        .instruction_stream
        .iter()
        .map(|sample| sample.vcpu_id)
        .collect::<Vec<_>>();

    assert_eq!(cursors, vec![0, 0, 1, 1, 2, 2, 0]);
}

#[test]
fn contract_a_multi_vcpu_uses_single_aggregate_time_axis() {
    let config = match ContractAConfig::new_with_icount_shift(
        image_digest(),
        "console=ttyS0",
        11,
        3,
        2,
        1,
    ) {
        Ok(config) => config,
        Err(error) => panic!("test Contract A config should be valid: {error}"),
    };

    let run = run_hashing(&config, &[], 7);
    let cursors = run
        .instruction_stream
        .iter()
        .map(|sample| sample.vcpu_id)
        .collect::<Vec<_>>();

    assert_eq!(cursors, vec![0, 0, 1, 1, 2, 2, 0]);
    assert_eq!(
        run.time_trajectory,
        vec![
            TimeTrajectorySample {
                aggregate_icount: 1,
                virtual_time_ns: 2,
            },
            TimeTrajectorySample {
                aggregate_icount: 2,
                virtual_time_ns: 4,
            },
            TimeTrajectorySample {
                aggregate_icount: 3,
                virtual_time_ns: 6,
            },
            TimeTrajectorySample {
                aggregate_icount: 4,
                virtual_time_ns: 8,
            },
            TimeTrajectorySample {
                aggregate_icount: 5,
                virtual_time_ns: 10,
            },
            TimeTrajectorySample {
                aggregate_icount: 6,
                virtual_time_ns: 12,
            },
            TimeTrajectorySample {
                aggregate_icount: 7,
                virtual_time_ns: 14,
            },
        ]
    );
    assert_eq!(run.time_fingerprint.final_icount, 7);
    assert_eq!(run.time_fingerprint.final_virtual_time_ns, 14);
}

#[test]
fn contract_a_multi_vcpu_fingerprint_includes_every_vcpu_and_rr_cursor() {
    let config = match ContractAConfig::new(image_digest(), "console=ttyS0", 11, 3, 2) {
        Ok(config) => config,
        Err(error) => panic!("test Contract A config should be valid: {error}"),
    };

    let run = run_hashing(&config, &[], 4);
    let samples = &run.multi_vcpu_fingerprint_trajectory;

    assert_eq!(samples.len(), 4);
    assert_eq!(
        samples
            .iter()
            .map(|sample| sample.aggregate_icount)
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
    for sample in samples {
        assert_eq!(
            sample
                .vcpu_registers
                .iter()
                .map(|register| register.vcpu_id)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }
    assert_eq!(samples[0].rr_cursor.current_vcpu, 0);
    assert_eq!(samples[0].rr_cursor.position_in_quantum, 1);
    assert_eq!(samples[0].rr_cursor.quantum_remaining, 1);
    assert_eq!(samples[1].rr_cursor.current_vcpu, 1);
    assert_eq!(samples[1].rr_cursor.position_in_quantum, 0);
    assert_eq!(samples[1].rr_cursor.quantum_remaining, 2);
    assert_eq!(
        samples[2]
            .vcpu_registers
            .iter()
            .map(|register| register.retired_instruction_count)
            .collect::<Vec<_>>(),
        vec![2, 1, 0]
    );
    let configured_vcpu_count = match usize::try_from(config.vcpu_count()) {
        Ok(count) => count,
        Err(error) => panic!("test vCPU count should fit usize: {error}"),
    };
    assert!(samples.iter().all(|sample| {
        sample.rr_cursor.rr_switch_quantum == 2
            && sample.vcpu_registers.len() == configured_vcpu_count
    }));
}

#[test]
fn contract_a_multi_vcpu_fingerprint_trajectory_is_bit_identical_across_runs() {
    let config = match ContractAConfig::new(image_digest(), "console=ttyS0", 42, 4, 3) {
        Ok(config) => config,
        Err(error) => panic!("test Contract A config should be valid: {error}"),
    };
    let inputs = vec![
        RecordedInput::new(0, b"boot".to_vec()),
        RecordedInput::new(5, b"timer".to_vec()),
        RecordedInput::new(8, b"net".to_vec()),
    ];

    let first = run_hashing(&config, &inputs, 10);
    let second = run_hashing(&config, &inputs, 10);

    assert_eq!(
        first
            .instruction_stream
            .iter()
            .map(|sample| sample.aggregate_icount)
            .collect::<Vec<_>>(),
        second
            .instruction_stream
            .iter()
            .map(|sample| sample.aggregate_icount)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        first.multi_vcpu_fingerprint_trajectory,
        second.multi_vcpu_fingerprint_trajectory
    );
    assert_eq!(first.fingerprint, second.fingerprint);
}

#[test]
fn contract_a_multi_vcpu_fingerprint_changes_when_register_file_changes() {
    let config = match ContractAConfig::new(image_digest(), "console=ttyS0", 11, 3, 2) {
        Ok(config) => config,
        Err(error) => panic!("test Contract A config should be valid: {error}"),
    };
    let mut baseline_vm = HashingContractAVm::default();
    let mut perturbed_vm = PerturbingRegisterVm::new(1);

    let baseline = match ContractADriver::run(&mut baseline_vm, &config, &[], 5) {
        Ok(run) => run,
        Err(error) => panic!("test Contract A run should be valid: {error}"),
    };
    let perturbed = match ContractADriver::run(&mut perturbed_vm, &config, &[], 5) {
        Ok(run) => run,
        Err(error) => panic!("test Contract A run should be valid: {error}"),
    };

    assert_eq!(baseline.instruction_stream, perturbed.instruction_stream);
    assert_eq!(
        baseline.architectural_state_trajectory,
        perturbed.architectural_state_trajectory
    );
    assert_ne!(
        baseline.multi_vcpu_fingerprint_trajectory,
        perturbed.multi_vcpu_fingerprint_trajectory
    );
    assert_ne!(baseline.fingerprint, perturbed.fingerprint);
}

#[test]
fn contract_a_rr_switch_quantum_is_content_addressed_node_icount_units() {
    let quantum_two = match ContractAConfig::new_with_icount_shift(
        image_digest(),
        "console=ttyS0",
        11,
        3,
        2,
        2,
    ) {
        Ok(config) => config,
        Err(error) => panic!("test Contract A config should be valid: {error}"),
    };
    let quantum_three = match ContractAConfig::new_with_icount_shift(
        image_digest(),
        "console=ttyS0",
        11,
        3,
        3,
        2,
    ) {
        Ok(config) => config,
        Err(error) => panic!("test Contract A config should be valid: {error}"),
    };

    let run_quantum_two = run_hashing(&quantum_two, &[], 7);
    let run_quantum_three = run_hashing(&quantum_three, &[], 7);
    let cursors_two = run_quantum_two
        .instruction_stream
        .iter()
        .map(|sample| sample.vcpu_id)
        .collect::<Vec<_>>();
    let cursors_three = run_quantum_three
        .instruction_stream
        .iter()
        .map(|sample| sample.vcpu_id)
        .collect::<Vec<_>>();

    assert_eq!(cursors_two, vec![0, 0, 1, 1, 2, 2, 0]);
    assert_eq!(cursors_three, vec![0, 0, 0, 1, 1, 1, 2]);
    assert_eq!(
        run_quantum_two.time_trajectory,
        run_quantum_three.time_trajectory
    );
    assert_ne!(run_quantum_two.fingerprint, run_quantum_three.fingerprint);
}

#[test]
fn contract_a_driver_rejects_non_monotonic_recorded_inputs() {
    let mut vm = HashingContractAVm::default();
    let error = match ContractADriver::run(
        &mut vm,
        &config(),
        &[
            RecordedInput::new(2, b"second".to_vec()),
            RecordedInput::new(1, b"first".to_vec()),
        ],
        8,
    ) {
        Ok(_) => panic!("non-monotonic recorded inputs should fail"),
        Err(error) => error,
    };

    assert_eq!(
        error,
        ContractAError::RecordedInputOrder {
            index: 1,
            delivery_icount: 1,
            previous_icount: 2,
        }
    );
}

#[test]
fn contract_a_driver_rejects_out_of_interval_recorded_inputs() {
    let mut vm = HashingContractAVm::default();
    let error = match ContractADriver::run(
        &mut vm,
        &config(),
        &[RecordedInput::new(8, b"late".to_vec())],
        8,
    ) {
        Ok(_) => panic!("out-of-interval recorded input should fail"),
        Err(error) => error,
    };

    assert_eq!(
        error,
        ContractAError::RecordedInputOutsideRun {
            index: 0,
            delivery_icount: 8,
            retired_instruction_count: 8,
        }
    );
}

#[test]
fn contract_a_config_and_driver_reject_zero_or_unbounded_parameters() {
    assert_eq!(
        ContractAConfig::new(image_digest(), "", 0, 0, 1),
        Err(ContractAConfigError::ZeroVcpuCount)
    );
    assert_eq!(
        ContractAConfig::new(image_digest(), "", 0, MAX_CONTRACT_A_VCPU_COUNT + 1, 1),
        Err(ContractAConfigError::VcpuCountTooLarge {
            count: MAX_CONTRACT_A_VCPU_COUNT + 1,
            max: MAX_CONTRACT_A_VCPU_COUNT,
        })
    );
    assert_eq!(
        ContractAConfig::new(image_digest(), "", 0, 1, 0),
        Err(ContractAConfigError::ZeroRrSwitchQuantum)
    );
    assert_eq!(
        ContractAConfig::new_with_icount_shift(
            image_digest(),
            "",
            0,
            1,
            1,
            MAX_CONTRACT_A_ICOUNT_SHIFT + 1,
        ),
        Err(ContractAConfigError::IcountShiftTooLarge {
            shift: MAX_CONTRACT_A_ICOUNT_SHIFT + 1,
            max: MAX_CONTRACT_A_ICOUNT_SHIFT,
        })
    );

    let mut vm = HashingContractAVm::default();
    assert_eq!(
        ContractADriver::run(
            &mut vm,
            &config(),
            &[],
            MAX_CONTRACT_A_RETIRED_INSTRUCTIONS + 1,
        ),
        Err(ContractAError::RetiredInstructionCountTooLarge {
            count: MAX_CONTRACT_A_RETIRED_INSTRUCTIONS + 1,
            max: MAX_CONTRACT_A_RETIRED_INSTRUCTIONS,
        })
    );
}

#[test]
fn contract_a_driver_rejects_unrepresentable_virtual_time() {
    let config = match ContractAConfig::new_with_icount_shift(
        image_digest(),
        "console=ttyS0",
        7,
        1,
        1,
        MAX_CONTRACT_A_ICOUNT_SHIFT,
    ) {
        Ok(config) => config,
        Err(error) => panic!("test Contract A config should be valid: {error}"),
    };
    let mut vm = HashingContractAVm::default();

    let error = match ContractADriver::run(&mut vm, &config, &[], 2) {
        Ok(_) => panic!("overflowing virtual time should fail"),
        Err(error) => error,
    };

    assert_eq!(
        error,
        ContractAError::VirtualTimeOverflow {
            aggregate_icount: 2,
            icount_shift: MAX_CONTRACT_A_ICOUNT_SHIFT,
        }
    );
}
