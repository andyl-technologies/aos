//! Contract A's isolated single-VM driver.
//!
//! Spec index: RFC-0010 files 04, 09.
//!
//! This module owns the pure L0 driver for Contract A: a single node receives an
//! already-recorded, icount-stamped input list and produces deterministic
//! instruction-stream and architectural-state samples. The driver has no
//! scheduler, peer, transport, QEMU, or wall-clock surface; it drives an
//! injected VM boundary so later crates can compare a real backend against the
//! same shape.
//!
//! Module map: [`ContractAConfig`] defines the fixed `run` inputs,
//! [`RecordedInput`] represents the recorded list `I`, [`ContractAVm`] is the
//! isolated VM execution boundary, [`ContractADriver`] feeds inputs and retires
//! aggregate instructions, and [`ContractARun`] carries the resulting stream,
//! trajectory, and digest.

use thiserror::Error;

use crate::{StableDigest, StableHasher};

/// The maximum retired-instruction count accepted by the in-process driver.
///
/// The Contract A driver stores per-instruction samples so it is intentionally
/// bounded. Real backend runs use the same conceptual contract but stream or
/// sample their fingerprints instead of retaining an unbounded vector.
pub const MAX_CONTRACT_A_RETIRED_INSTRUCTIONS: u64 = 1_000_000;

/// Fixed inputs to Contract A's `run(image, cmdline, seed, I)` function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractAConfig {
    image: StableDigest,
    cmdline: String,
    seed: u64,
    vcpu_count: u64,
    rr_switch_quantum: u64,
}

impl ContractAConfig {
    /// Builds a validated single-VM Contract A configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ContractAConfigError`] when `vcpu_count` is zero or
    /// `rr_switch_quantum` is zero.
    pub fn new(
        image: StableDigest,
        cmdline: impl Into<String>,
        seed: u64,
        vcpu_count: u64,
        rr_switch_quantum: u64,
    ) -> Result<Self, ContractAConfigError> {
        if vcpu_count == 0 {
            return Err(ContractAConfigError::ZeroVcpuCount);
        }
        if rr_switch_quantum == 0 {
            return Err(ContractAConfigError::ZeroRrSwitchQuantum);
        }

        Ok(Self {
            image,
            cmdline: cmdline.into(),
            seed,
            vcpu_count,
            rr_switch_quantum,
        })
    }

    /// Returns the content digest identifying the VM image under test.
    #[must_use]
    pub fn image(&self) -> StableDigest {
        self.image
    }

    /// Returns the fixed kernel command line for the run.
    #[must_use]
    pub fn cmdline(&self) -> &str {
        &self.cmdline
    }

    /// Returns the root scenario seed for the isolated VM.
    #[must_use]
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Returns the fixed vCPU count for the node.
    #[must_use]
    pub fn vcpu_count(&self) -> u64 {
        self.vcpu_count
    }

    /// Returns the fixed RR switch quantum in aggregate node-icount units.
    #[must_use]
    pub fn rr_switch_quantum(&self) -> u64 {
        self.rr_switch_quantum
    }

    fn write_hash_material(&self, hasher: &mut StableHasher) {
        hasher.write_tag("contract-a-config-v1");
        hasher.write_bytes(&self.image.bytes);
        hasher.write_bytes(self.cmdline.as_bytes());
        hasher.write_u64(self.seed);
        hasher.write_u64(self.vcpu_count);
        hasher.write_u64(self.rr_switch_quantum);
    }
}

/// A validation error for [`ContractAConfig`].
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ContractAConfigError {
    /// The VM must contain at least one vCPU.
    #[error("Contract A requires at least one vCPU")]
    ZeroVcpuCount,

    /// The round-robin switch quantum must be a non-zero node-icount value.
    #[error("Contract A requires a non-zero RR switch quantum")]
    ZeroRrSwitchQuantum,
}

/// One recorded input from the fixed list `I`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedInput {
    delivery_icount: u64,
    payload: Vec<u8>,
}

impl RecordedInput {
    /// Builds a recorded input visible at `delivery_icount`.
    #[must_use]
    pub fn new(delivery_icount: u64, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            delivery_icount,
            payload: payload.into(),
        }
    }

    /// Returns the aggregate icount at which the input becomes visible.
    #[must_use]
    pub fn delivery_icount(&self) -> u64 {
        self.delivery_icount
    }

    /// Returns the recorded payload bytes for the input.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    fn write_hash_material(&self, hasher: &mut StableHasher) {
        hasher.write_tag("contract-a-recorded-input-v1");
        hasher.write_u64(self.delivery_icount);
        hasher.write_bytes(&self.payload);
    }
}

/// A VM execution boundary that can be driven by [`ContractADriver`].
pub trait ContractAVm {
    /// Resets the isolated VM to the fixed Contract A configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ContractAExecutionError`] if the VM cannot enter the requested
    /// initial state.
    fn reset(&mut self, config: &ContractAConfig) -> Result<(), ContractAExecutionError>;

    /// Makes one recorded input architecturally visible.
    ///
    /// # Errors
    ///
    /// Returns [`ContractAExecutionError`] if the VM rejects the input at the
    /// delivery point selected by the driver.
    fn inject_recorded_input(
        &mut self,
        input: &RecordedInput,
    ) -> Result<(), ContractAExecutionError>;

    /// Retires one aggregate node instruction.
    ///
    /// # Errors
    ///
    /// Returns [`ContractAExecutionError`] if the VM cannot retire the requested
    /// instruction from its current state.
    fn retire_instruction(
        &mut self,
        request: RetireRequest,
    ) -> Result<StableDigest, ContractAExecutionError>;

    /// Samples the architectural state after an instruction retires.
    ///
    /// # Errors
    ///
    /// Returns [`ContractAExecutionError`] if the VM cannot provide a stable
    /// architectural-state digest at `aggregate_icount`.
    fn sample_architectural_state(
        &mut self,
        aggregate_icount: u64,
    ) -> Result<StableDigest, ContractAExecutionError>;
}

/// The aggregate instruction that [`ContractADriver`] asks a VM to retire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetireRequest {
    /// The aggregate node icount before the instruction retires.
    pub aggregate_before: u64,
    /// The aggregate node icount after the instruction retires.
    pub aggregate_icount: u64,
    /// The deterministic RR vCPU cursor selected for this instruction.
    pub vcpu_id: u64,
    /// The number of recorded inputs made visible before this instruction.
    pub visible_input_count: u64,
}

/// A deterministic in-process VM double for isolated Contract A tests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HashingContractAVm {
    config: Option<ContractAConfig>,
    state_digest: StableDigest,
}

impl ContractAVm for HashingContractAVm {
    fn reset(&mut self, config: &ContractAConfig) -> Result<(), ContractAExecutionError> {
        let mut hasher = StableHasher::new();
        hasher.write_tag("contract-a-vm-reset-v1");
        config.write_hash_material(&mut hasher);
        self.config = Some(config.clone());
        self.state_digest = hasher.finish();
        Ok(())
    }

    fn inject_recorded_input(
        &mut self,
        input: &RecordedInput,
    ) -> Result<(), ContractAExecutionError> {
        let config = self.config()?;
        let mut hasher = StableHasher::new();
        hasher.write_tag("contract-a-vm-input-v1");
        config.write_hash_material(&mut hasher);
        hasher.write_bytes(&self.state_digest.bytes);
        input.write_hash_material(&mut hasher);
        self.state_digest = hasher.finish();
        Ok(())
    }

    fn retire_instruction(
        &mut self,
        request: RetireRequest,
    ) -> Result<StableDigest, ContractAExecutionError> {
        let config = self.config()?;
        let mut instruction = StableHasher::new();
        instruction.write_tag("contract-a-vm-instruction-v1");
        config.write_hash_material(&mut instruction);
        instruction.write_bytes(&self.state_digest.bytes);
        instruction.write_u64(request.aggregate_before);
        instruction.write_u64(request.aggregate_icount);
        instruction.write_u64(request.vcpu_id);
        instruction.write_u64(request.visible_input_count);
        let operation_digest = instruction.finish();

        let mut state = StableHasher::new();
        state.write_tag("contract-a-vm-state-v1");
        config.write_hash_material(&mut state);
        state.write_bytes(&self.state_digest.bytes);
        state.write_bytes(&operation_digest.bytes);
        state.write_u64(request.aggregate_icount);
        state.write_u64(request.vcpu_id);
        state.write_u64(request.visible_input_count);
        self.state_digest = state.finish();

        Ok(operation_digest)
    }

    fn sample_architectural_state(
        &mut self,
        aggregate_icount: u64,
    ) -> Result<StableDigest, ContractAExecutionError> {
        let mut hasher = StableHasher::new();
        hasher.write_tag("contract-a-vm-state-sample-v1");
        hasher.write_bytes(&self.state_digest.bytes);
        hasher.write_u64(aggregate_icount);
        Ok(hasher.finish())
    }
}

impl HashingContractAVm {
    fn config(&self) -> Result<&ContractAConfig, ContractAExecutionError> {
        self.config
            .as_ref()
            .ok_or_else(|| ContractAExecutionError::new("Contract A VM is not reset"))
    }
}

/// A backend execution error reported through the Contract A driver.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{message}")]
pub struct ContractAExecutionError {
    message: String,
}

impl ContractAExecutionError {
    /// Builds a backend execution error.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the backend-provided error message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// An isolated Contract A driver with no scheduler or transport dependency.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ContractADriver;

impl ContractADriver {
    /// Runs a VM against a recorded input list in Contract A isolation.
    ///
    /// Inputs stamped with icount `k` are injected before the instruction that
    /// advances the node from aggregate icount `k` to `k + 1`. Inputs with the
    /// same delivery icount are injected in recorded-list order. The driver does
    /// not observe host time, transport arrival, live peers, or a scheduler.
    ///
    /// # Errors
    ///
    /// Returns [`ContractAError`] if the recorded input list is invalid, the run
    /// length exceeds the in-process bound, or the VM reports an execution
    /// error.
    pub fn run<Vm: ContractAVm>(
        vm: &mut Vm,
        config: &ContractAConfig,
        inputs: &[RecordedInput],
        retired_instruction_count: u64,
    ) -> Result<ContractARun, ContractAError> {
        validate_recorded_inputs(retired_instruction_count, inputs)?;
        vm.reset(config)
            .map_err(|source| ContractAError::VmReset { source })?;

        let mut instruction_stream = Vec::new();
        let mut architectural_state_trajectory = Vec::new();
        let input_digest = recorded_input_digest(inputs);
        let mut input_index = 0;

        for aggregate_before in 0..retired_instruction_count {
            let visible_inputs_start = input_index;
            while input_index < inputs.len()
                && inputs[input_index].delivery_icount == aggregate_before
            {
                vm.inject_recorded_input(&inputs[input_index])
                    .map_err(|source| ContractAError::VmInput {
                        index: input_index,
                        delivery_icount: inputs[input_index].delivery_icount,
                        source,
                    })?;
                input_index += 1;
            }

            let visible_input_count = (input_index - visible_inputs_start) as u64;
            let aggregate_icount = aggregate_before + 1;
            let vcpu_id = vcpu_for_icount(config, aggregate_before);
            let request = RetireRequest {
                aggregate_before,
                aggregate_icount,
                vcpu_id,
                visible_input_count,
            };
            let operation_digest =
                vm.retire_instruction(request)
                    .map_err(|source| ContractAError::VmRetire {
                        aggregate_icount,
                        source,
                    })?;
            let state_digest =
                vm.sample_architectural_state(aggregate_icount)
                    .map_err(|source| ContractAError::VmStateSample {
                        aggregate_icount,
                        source,
                    })?;

            instruction_stream.push(InstructionSample {
                aggregate_icount,
                vcpu_id,
                visible_input_count,
                operation_digest,
            });
            architectural_state_trajectory.push(ArchitecturalStateSample {
                aggregate_icount,
                state_digest,
            });
        }

        let fingerprint = run_fingerprint(
            config,
            input_digest,
            &instruction_stream,
            &architectural_state_trajectory,
        );

        Ok(ContractARun {
            instruction_stream,
            architectural_state_trajectory,
            input_digest,
            fingerprint,
        })
    }
}

/// A completed isolated Contract A run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractARun {
    /// The modeled aggregate-icount instruction stream `S`.
    pub instruction_stream: Vec<InstructionSample>,
    /// The modeled architectural-state trajectory `T`.
    pub architectural_state_trajectory: Vec<ArchitecturalStateSample>,
    /// The stable digest of the recorded input list used for this run.
    pub input_digest: StableDigest,
    /// A stable digest over the fixed run inputs and all produced samples.
    pub fingerprint: StableDigest,
}

/// One aggregate-icount instruction-stream sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstructionSample {
    /// The aggregate node icount after this instruction retired.
    pub aggregate_icount: u64,
    /// The deterministic RR vCPU cursor selected for this instruction.
    pub vcpu_id: u64,
    /// The number of recorded inputs made visible before this instruction.
    pub visible_input_count: u64,
    /// The stable digest of the modeled decoded operation.
    pub operation_digest: StableDigest,
}

/// One aggregate-icount architectural-state sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchitecturalStateSample {
    /// The aggregate node icount at which this state was sampled.
    pub aggregate_icount: u64,
    /// The stable digest of the modeled architectural state.
    pub state_digest: StableDigest,
}

/// A recorded-input or backend execution error for [`ContractADriver`].
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ContractAError {
    /// A later entry in the recorded list has an earlier delivery icount.
    #[error(
        "recorded input at index {index} has delivery icount {delivery_icount}, \
         which is earlier than previous delivery icount {previous_icount}"
    )]
    RecordedInputOrder {
        /// The offending input index.
        index: usize,
        /// The offending input's delivery icount.
        delivery_icount: u64,
        /// The previous input's delivery icount.
        previous_icount: u64,
    },

    /// A recorded input would become visible outside the modeled run.
    #[error(
        "recorded input at index {index} has delivery icount {delivery_icount}, \
         outside retired-instruction count {retired_instruction_count}"
    )]
    RecordedInputOutsideRun {
        /// The offending input index.
        index: usize,
        /// The offending input's delivery icount.
        delivery_icount: u64,
        /// The modeled retired-instruction count.
        retired_instruction_count: u64,
    },

    /// The bounded in-process driver was asked to retain too many samples.
    #[error("Contract A retired-instruction count {count} exceeds the in-process bound {max}")]
    RetiredInstructionCountTooLarge {
        /// The requested retired-instruction count.
        count: u64,
        /// The maximum accepted retired-instruction count.
        max: u64,
    },

    /// The VM failed while resetting to the requested configuration.
    #[error("Contract A VM reset failed: {source}")]
    VmReset {
        /// The backend execution error.
        source: ContractAExecutionError,
    },

    /// The VM failed while injecting one recorded input.
    #[error(
        "Contract A VM input injection failed at index {index}, delivery icount \
         {delivery_icount}: {source}"
    )]
    VmInput {
        /// The offending input index.
        index: usize,
        /// The offending input's delivery icount.
        delivery_icount: u64,
        /// The backend execution error.
        source: ContractAExecutionError,
    },

    /// The VM failed while retiring one aggregate instruction.
    #[error("Contract A VM retire failed at aggregate icount {aggregate_icount}: {source}")]
    VmRetire {
        /// The aggregate icount after the requested instruction would retire.
        aggregate_icount: u64,
        /// The backend execution error.
        source: ContractAExecutionError,
    },

    /// The VM failed while sampling architectural state.
    #[error("Contract A VM state sample failed at aggregate icount {aggregate_icount}: {source}")]
    VmStateSample {
        /// The aggregate icount being sampled.
        aggregate_icount: u64,
        /// The backend execution error.
        source: ContractAExecutionError,
    },
}

fn validate_recorded_inputs(
    retired_instruction_count: u64,
    inputs: &[RecordedInput],
) -> Result<(), ContractAError> {
    if retired_instruction_count > MAX_CONTRACT_A_RETIRED_INSTRUCTIONS {
        return Err(ContractAError::RetiredInstructionCountTooLarge {
            count: retired_instruction_count,
            max: MAX_CONTRACT_A_RETIRED_INSTRUCTIONS,
        });
    }

    let mut previous = None;
    for (index, input) in inputs.iter().enumerate() {
        if let Some(previous_icount) = previous {
            if input.delivery_icount < previous_icount {
                return Err(ContractAError::RecordedInputOrder {
                    index,
                    delivery_icount: input.delivery_icount,
                    previous_icount,
                });
            }
        }
        if input.delivery_icount >= retired_instruction_count {
            return Err(ContractAError::RecordedInputOutsideRun {
                index,
                delivery_icount: input.delivery_icount,
                retired_instruction_count,
            });
        }
        previous = Some(input.delivery_icount);
    }
    Ok(())
}

fn vcpu_for_icount(config: &ContractAConfig, aggregate_icount: u64) -> u64 {
    (aggregate_icount / config.rr_switch_quantum) % config.vcpu_count
}

fn recorded_input_digest(inputs: &[RecordedInput]) -> StableDigest {
    let mut hasher = StableHasher::new();
    hasher.write_tag("contract-a-recorded-input-list-v1");
    hasher.write_u64(inputs.len() as u64);
    for input in inputs {
        input.write_hash_material(&mut hasher);
    }
    hasher.finish()
}

fn run_fingerprint(
    config: &ContractAConfig,
    input_digest: StableDigest,
    instruction_stream: &[InstructionSample],
    architectural_state_trajectory: &[ArchitecturalStateSample],
) -> StableDigest {
    let mut hasher = StableHasher::new();
    hasher.write_tag("contract-a-run-v1");
    config.write_hash_material(&mut hasher);
    hasher.write_bytes(&input_digest.bytes);
    hasher.write_u64(instruction_stream.len() as u64);
    for sample in instruction_stream {
        hasher.write_u64(sample.aggregate_icount);
        hasher.write_u64(sample.vcpu_id);
        hasher.write_u64(sample.visible_input_count);
        hasher.write_bytes(&sample.operation_digest.bytes);
    }
    hasher.write_u64(architectural_state_trajectory.len() as u64);
    for sample in architectural_state_trajectory {
        hasher.write_u64(sample.aggregate_icount);
        hasher.write_bytes(&sample.state_digest.bytes);
    }
    hasher.finish()
}
