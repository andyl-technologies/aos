//! Contract A's isolated single-VM driver.
//!
//! Spec index: RFC-0010 files 04, 09.
//!
//! This module owns the pure L0 driver for Contract A: a single node receives an
//! already-recorded, icount-stamped input list and produces deterministic
//! instruction-stream, architectural-state, and virtual-time samples. The
//! driver has no scheduler, peer, transport, QEMU, or wall-clock surface; it
//! drives an injected VM boundary so later crates can compare a real backend
//! against the same shape.
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
/// The Contract A driver stores per-instruction samples in memory, so each run
/// dimension is intentionally bounded. Real backend runs use the same conceptual
/// contract but stream or sample their fingerprints instead of retaining an
/// unbounded vector.
pub const MAX_CONTRACT_A_RETIRED_INSTRUCTIONS: u64 = 1_000_000;

/// The maximum vCPU count accepted by the in-process Contract A driver.
///
/// Real backend launches may support larger topology limits, but this model
/// stores per-vCPU samples in memory and therefore bounds the fixture topology.
pub const MAX_CONTRACT_A_VCPU_COUNT: u64 = 4096;

/// The default fixed `-icount shift=N` used by the isolated model.
pub const DEFAULT_CONTRACT_A_ICOUNT_SHIFT: u8 = 0;

/// The largest shift that can name a `u64` power-of-two scale.
pub const MAX_CONTRACT_A_ICOUNT_SHIFT: u8 = 63;

/// Fixed inputs to Contract A's `run(image, cmdline, seed, I)` function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractAConfig {
    image: StableDigest,
    cmdline: String,
    seed: u64,
    vcpu_count: u64,
    rr_switch_quantum: u64,
    icount_shift: u8,
}

impl ContractAConfig {
    /// Builds a validated single-VM Contract A configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ContractAConfigError`] when `vcpu_count` is zero,
    /// `vcpu_count` exceeds [`MAX_CONTRACT_A_VCPU_COUNT`], or
    /// `rr_switch_quantum` is zero.
    pub fn new(
        image: StableDigest,
        cmdline: impl Into<String>,
        seed: u64,
        vcpu_count: u64,
        rr_switch_quantum: u64,
    ) -> Result<Self, ContractAConfigError> {
        Self::new_with_icount_shift(
            image,
            cmdline,
            seed,
            vcpu_count,
            rr_switch_quantum,
            DEFAULT_CONTRACT_A_ICOUNT_SHIFT,
        )
    }

    /// Builds a validated single-VM Contract A configuration with an explicit
    /// fixed shift.
    ///
    /// # Errors
    ///
    /// Returns [`ContractAConfigError`] when `vcpu_count` is zero,
    /// `vcpu_count` exceeds [`MAX_CONTRACT_A_VCPU_COUNT`],
    /// `rr_switch_quantum` is zero, or `icount_shift` cannot name a `u64`
    /// power-of-two virtual-time scale.
    pub fn new_with_icount_shift(
        image: StableDigest,
        cmdline: impl Into<String>,
        seed: u64,
        vcpu_count: u64,
        rr_switch_quantum: u64,
        icount_shift: u8,
    ) -> Result<Self, ContractAConfigError> {
        if vcpu_count == 0 {
            return Err(ContractAConfigError::ZeroVcpuCount);
        }
        if vcpu_count > MAX_CONTRACT_A_VCPU_COUNT {
            return Err(ContractAConfigError::VcpuCountTooLarge {
                count: vcpu_count,
                max: MAX_CONTRACT_A_VCPU_COUNT,
            });
        }
        if rr_switch_quantum == 0 {
            return Err(ContractAConfigError::ZeroRrSwitchQuantum);
        }
        if icount_shift > MAX_CONTRACT_A_ICOUNT_SHIFT {
            return Err(ContractAConfigError::IcountShiftTooLarge {
                shift: icount_shift,
                max: MAX_CONTRACT_A_ICOUNT_SHIFT,
            });
        }

        Ok(Self {
            image,
            cmdline: cmdline.into(),
            seed,
            vcpu_count,
            rr_switch_quantum,
            icount_shift,
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

    /// Returns the fixed `-icount shift=N` scale for virtual-time projection.
    #[must_use]
    pub fn icount_shift(&self) -> u8 {
        self.icount_shift
    }

    fn write_hash_material(&self, hasher: &mut StableHasher) {
        hasher.write_tag("contract-a-config-v1");
        hasher.write_bytes(&self.image.bytes);
        hasher.write_bytes(self.cmdline.as_bytes());
        hasher.write_u64(self.seed);
        hasher.write_u64(self.vcpu_count);
        hasher.write_u64(self.rr_switch_quantum);
        hasher.write_u64(u64::from(self.icount_shift));
    }
}

/// A validation error for [`ContractAConfig`].
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ContractAConfigError {
    /// The VM must contain at least one vCPU.
    #[error("Contract A requires at least one vCPU")]
    ZeroVcpuCount,

    /// The in-process driver cannot retain per-vCPU state for this topology.
    #[error("Contract A vCPU count {count} exceeds the in-process bound {max}")]
    VcpuCountTooLarge {
        /// The requested vCPU count.
        count: u64,
        /// The maximum accepted vCPU count.
        max: u64,
    },

    /// The round-robin switch quantum must be a non-zero node-icount value.
    #[error("Contract A requires a non-zero RR switch quantum")]
    ZeroRrSwitchQuantum,

    /// The fixed icount shift cannot name a `u64` virtual-time scale.
    #[error("Contract A icount shift {shift} exceeds the maximum supported shift {max}")]
    IcountShiftTooLarge {
        /// The requested fixed shift.
        shift: u8,
        /// The maximum accepted fixed shift.
        max: u8,
    },
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

    /// Samples one vCPU register file for the multi-vCPU execution fingerprint.
    ///
    /// # Errors
    ///
    /// Returns [`ContractAExecutionError`] if the VM cannot provide a stable
    /// register-file digest for the requested vCPU at the aggregate icount.
    fn sample_vcpu_register_file(
        &mut self,
        request: VcpuRegisterFileRequest,
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

/// A request to sample one modeled vCPU register file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VcpuRegisterFileRequest {
    /// The aggregate node icount at which the fingerprint is sampled.
    pub aggregate_icount: u64,
    /// The vCPU whose register file is being sampled.
    pub vcpu_id: u64,
    /// The RR cursor's current vCPU at this aggregate icount boundary.
    pub current_vcpu: u64,
    /// Position within the fixed RR switch quantum.
    pub position_in_quantum: u64,
    /// Remaining aggregate instructions before the next RR switch boundary.
    pub quantum_remaining: u64,
    /// Instructions retired by this vCPU at the sample point.
    pub vcpu_retired_instruction_count: u64,
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

    fn sample_vcpu_register_file(
        &mut self,
        request: VcpuRegisterFileRequest,
    ) -> Result<StableDigest, ContractAExecutionError> {
        let config = self.config()?;
        let mut hasher = StableHasher::new();
        hasher.write_tag("contract-a-vcpu-register-file-v1");
        config.write_hash_material(&mut hasher);
        hasher.write_bytes(&self.state_digest.bytes);
        hasher.write_u64(request.aggregate_icount);
        hasher.write_u64(request.vcpu_id);
        hasher.write_u64(request.current_vcpu);
        hasher.write_u64(request.position_in_quantum);
        hasher.write_u64(request.quantum_remaining);
        hasher.write_u64(request.vcpu_retired_instruction_count);
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
    /// shape exceeds an in-process bound, or the VM reports a reset, injection,
    /// execution, or sampling error.
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
        let mut time_trajectory = Vec::new();
        let mut multi_vcpu_fingerprint_trajectory = Vec::new();
        let vcpu_count = runtime_vcpu_count(config)?;
        let mut per_vcpu_retired_counts = vec![0_u64; vcpu_count];
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
            let vcpu_index =
                usize::try_from(vcpu_id).map_err(|_error| ContractAError::VcpuCountTooLarge {
                    count: config.vcpu_count,
                    max: MAX_CONTRACT_A_VCPU_COUNT,
                })?;
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
            per_vcpu_retired_counts[vcpu_index] += 1;
            let state_digest =
                vm.sample_architectural_state(aggregate_icount)
                    .map_err(|source| ContractAError::VmStateSample {
                        aggregate_icount,
                        source,
                    })?;
            let virtual_time_ns = virtual_time_for_icount(aggregate_icount, config.icount_shift)?;
            let rr_cursor = rr_cursor_for_aggregate_icount(config, aggregate_icount);
            let multi_vcpu_fingerprint = multi_vcpu_fingerprint_sample(
                vm,
                aggregate_icount,
                rr_cursor,
                &per_vcpu_retired_counts,
            )?;

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
            time_trajectory.push(TimeTrajectorySample {
                aggregate_icount,
                virtual_time_ns,
            });
            multi_vcpu_fingerprint_trajectory.push(multi_vcpu_fingerprint);
        }

        let time_fingerprint = time_fingerprint(config.icount_shift, &time_trajectory);
        let fingerprint = run_fingerprint(
            config,
            input_digest,
            &instruction_stream,
            &architectural_state_trajectory,
            &time_trajectory,
            &multi_vcpu_fingerprint_trajectory,
            time_fingerprint,
        );

        Ok(ContractARun {
            instruction_stream,
            architectural_state_trajectory,
            time_trajectory,
            multi_vcpu_fingerprint_trajectory,
            input_digest,
            time_fingerprint,
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
    /// The modeled `(icount, virtual_time)` trajectory.
    pub time_trajectory: Vec<TimeTrajectorySample>,
    /// Per-vCPU register-file and RR-cursor samples keyed by aggregate icount.
    pub multi_vcpu_fingerprint_trajectory: Vec<ContractAMultiVcpuFingerprintSample>,
    /// The stable digest of the recorded input list used for this run.
    pub input_digest: StableDigest,
    /// A stable digest over only time-derived fingerprint fields.
    pub time_fingerprint: ContractATimeFingerprint,
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

/// One Contract A virtual-time trajectory sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeTrajectorySample {
    /// The aggregate node icount after this instruction retired.
    pub aggregate_icount: u64,
    /// Virtual nanoseconds derived as `aggregate_icount << icount_shift`.
    pub virtual_time_ns: u64,
}

/// One multi-vCPU execution fingerprint sample.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractAMultiVcpuFingerprintSample {
    /// The aggregate node icount at which all fields were sampled.
    pub aggregate_icount: u64,
    /// Register-file digests for every vCPU in ascending vCPU order.
    pub vcpu_registers: Vec<ContractAVcpuRegisterFileSample>,
    /// Round-robin cursor state at the same aggregate icount boundary.
    pub rr_cursor: ContractARoundRobinCursorSample,
    /// Stable digest over the sample's per-vCPU and cursor material.
    pub sample_digest: StableDigest,
}

/// One modeled vCPU register-file fingerprint entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContractAVcpuRegisterFileSample {
    /// The vCPU whose register file was sampled.
    pub vcpu_id: u64,
    /// Digest of the vCPU's architectural register file.
    pub register_digest: StableDigest,
    /// Instructions retired by this vCPU at the aggregate sample point.
    pub retired_instruction_count: u64,
}

/// Round-robin cursor state included in each multi-vCPU fingerprint sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContractARoundRobinCursorSample {
    /// The next vCPU selected by the fixed RR rotation.
    pub current_vcpu: u64,
    /// Position inside the current fixed RR switch quantum.
    pub position_in_quantum: u64,
    /// Remaining aggregate instructions before the next RR switch boundary.
    pub quantum_remaining: u64,
    /// The fixed RR switch quantum in aggregate node-icount units.
    pub rr_switch_quantum: u64,
}

/// Stable fingerprint material derived only from the Contract A time trajectory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContractATimeFingerprint {
    /// The fixed `-icount shift=N` used for this trajectory.
    pub icount_shift: u8,
    /// The final aggregate icount sampled in the trajectory.
    pub final_icount: u64,
    /// The final virtual nanosecond value sampled in the trajectory.
    pub final_virtual_time_ns: u64,
    /// The stable digest of every `(icount, virtual_time)` pair.
    pub trajectory_digest: StableDigest,
    /// The stable digest of the execution-fingerprint fields derived from time.
    pub time_derived_fields_digest: StableDigest,
}

impl ContractATimeFingerprint {
    fn write_hash_material(&self, hasher: &mut StableHasher) {
        hasher.write_tag("contract-a-time-fingerprint-v1");
        hasher.write_u64(u64::from(self.icount_shift));
        hasher.write_u64(self.final_icount);
        hasher.write_u64(self.final_virtual_time_ns);
        hasher.write_bytes(&self.trajectory_digest.bytes);
        hasher.write_bytes(&self.time_derived_fields_digest.bytes);
    }
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

    /// A `(icount << shift)` virtual-time projection cannot fit in `u64`.
    #[error(
        "Contract A virtual time overflows at aggregate icount {aggregate_icount} \
         with icount shift {icount_shift}"
    )]
    VirtualTimeOverflow {
        /// The aggregate icount being projected.
        aggregate_icount: u64,
        /// The fixed icount shift used by the run.
        icount_shift: u8,
    },

    /// The in-process driver cannot retain per-vCPU state for this topology.
    #[error("Contract A vCPU count {count} exceeds the in-process bound {max}")]
    VcpuCountTooLarge {
        /// The requested vCPU count.
        count: u64,
        /// The maximum accepted vCPU count.
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

    /// The VM failed while sampling one vCPU register file.
    #[error(
        "Contract A VM vCPU register sample failed at aggregate icount \
         {aggregate_icount}, vCPU {vcpu_id}: {source}"
    )]
    VmVcpuRegisterSample {
        /// The aggregate icount being sampled.
        aggregate_icount: u64,
        /// The vCPU whose register file was requested.
        vcpu_id: u64,
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
        if let Some(previous_icount) = previous
            && input.delivery_icount < previous_icount
        {
            return Err(ContractAError::RecordedInputOrder {
                index,
                delivery_icount: input.delivery_icount,
                previous_icount,
            });
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

fn runtime_vcpu_count(config: &ContractAConfig) -> Result<usize, ContractAError> {
    usize::try_from(config.vcpu_count).map_err(|_error| ContractAError::VcpuCountTooLarge {
        count: config.vcpu_count,
        max: MAX_CONTRACT_A_VCPU_COUNT,
    })
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

fn virtual_time_for_icount(aggregate_icount: u64, icount_shift: u8) -> Result<u64, ContractAError> {
    let scale = match 1u64.checked_shl(u32::from(icount_shift)) {
        Some(scale) => scale,
        None => {
            return Err(ContractAError::VirtualTimeOverflow {
                aggregate_icount,
                icount_shift,
            });
        }
    };
    aggregate_icount
        .checked_mul(scale)
        .ok_or(ContractAError::VirtualTimeOverflow {
            aggregate_icount,
            icount_shift,
        })
}

fn time_fingerprint(
    icount_shift: u8,
    time_trajectory: &[TimeTrajectorySample],
) -> ContractATimeFingerprint {
    let mut trajectory_hasher = StableHasher::new();
    trajectory_hasher.write_tag("contract-a-time-trajectory-v1");
    trajectory_hasher.write_u64(u64::from(icount_shift));
    trajectory_hasher.write_u64(time_trajectory.len() as u64);
    for sample in time_trajectory {
        trajectory_hasher.write_u64(sample.aggregate_icount);
        trajectory_hasher.write_u64(sample.virtual_time_ns);
    }
    let trajectory_digest = trajectory_hasher.finish();

    let final_icount = time_trajectory
        .last()
        .map_or(0, |sample| sample.aggregate_icount);
    let final_virtual_time_ns = time_trajectory
        .last()
        .map_or(0, |sample| sample.virtual_time_ns);

    let mut fields_hasher = StableHasher::new();
    fields_hasher.write_tag("contract-a-time-derived-fields-v1");
    fields_hasher.write_u64(u64::from(icount_shift));
    fields_hasher.write_u64(final_icount);
    fields_hasher.write_u64(final_virtual_time_ns);
    fields_hasher.write_bytes(&trajectory_digest.bytes);
    let time_derived_fields_digest = fields_hasher.finish();

    ContractATimeFingerprint {
        icount_shift,
        final_icount,
        final_virtual_time_ns,
        trajectory_digest,
        time_derived_fields_digest,
    }
}

fn rr_cursor_for_aggregate_icount(
    config: &ContractAConfig,
    aggregate_icount: u64,
) -> ContractARoundRobinCursorSample {
    let position_in_quantum = aggregate_icount % config.rr_switch_quantum;
    let quantum_remaining = if position_in_quantum == 0 {
        config.rr_switch_quantum
    } else {
        config.rr_switch_quantum - position_in_quantum
    };

    ContractARoundRobinCursorSample {
        current_vcpu: vcpu_for_icount(config, aggregate_icount),
        position_in_quantum,
        quantum_remaining,
        rr_switch_quantum: config.rr_switch_quantum,
    }
}

fn multi_vcpu_fingerprint_sample<Vm: ContractAVm>(
    vm: &mut Vm,
    aggregate_icount: u64,
    rr_cursor: ContractARoundRobinCursorSample,
    per_vcpu_retired_counts: &[u64],
) -> Result<ContractAMultiVcpuFingerprintSample, ContractAError> {
    let mut vcpu_registers = Vec::with_capacity(per_vcpu_retired_counts.len());

    for (vcpu_index, retired_instruction_count) in per_vcpu_retired_counts.iter().enumerate() {
        let vcpu_id =
            u64::try_from(vcpu_index).map_err(|_error| ContractAError::VcpuCountTooLarge {
                count: MAX_CONTRACT_A_VCPU_COUNT + 1,
                max: MAX_CONTRACT_A_VCPU_COUNT,
            })?;
        let request = VcpuRegisterFileRequest {
            aggregate_icount,
            vcpu_id,
            current_vcpu: rr_cursor.current_vcpu,
            position_in_quantum: rr_cursor.position_in_quantum,
            quantum_remaining: rr_cursor.quantum_remaining,
            vcpu_retired_instruction_count: *retired_instruction_count,
        };
        let register_digest = vm.sample_vcpu_register_file(request).map_err(|source| {
            ContractAError::VmVcpuRegisterSample {
                aggregate_icount,
                vcpu_id,
                source,
            }
        })?;
        vcpu_registers.push(ContractAVcpuRegisterFileSample {
            vcpu_id,
            register_digest,
            retired_instruction_count: *retired_instruction_count,
        });
    }

    let sample_digest =
        multi_vcpu_fingerprint_sample_digest(aggregate_icount, &vcpu_registers, rr_cursor);

    Ok(ContractAMultiVcpuFingerprintSample {
        aggregate_icount,
        vcpu_registers,
        rr_cursor,
        sample_digest,
    })
}

fn multi_vcpu_fingerprint_sample_digest(
    aggregate_icount: u64,
    vcpu_registers: &[ContractAVcpuRegisterFileSample],
    rr_cursor: ContractARoundRobinCursorSample,
) -> StableDigest {
    let mut hasher = StableHasher::new();
    hasher.write_tag("contract-a-multi-vcpu-fingerprint-sample-v1");
    hasher.write_u64(aggregate_icount);
    hasher.write_u64(len_for_hash(vcpu_registers.len()));
    for register in vcpu_registers {
        hasher.write_u64(register.vcpu_id);
        hasher.write_bytes(&register.register_digest.bytes);
        hasher.write_u64(register.retired_instruction_count);
    }
    hasher.write_u64(rr_cursor.current_vcpu);
    hasher.write_u64(rr_cursor.position_in_quantum);
    hasher.write_u64(rr_cursor.quantum_remaining);
    hasher.write_u64(rr_cursor.rr_switch_quantum);
    hasher.finish()
}

fn len_for_hash(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn run_fingerprint(
    config: &ContractAConfig,
    input_digest: StableDigest,
    instruction_stream: &[InstructionSample],
    architectural_state_trajectory: &[ArchitecturalStateSample],
    time_trajectory: &[TimeTrajectorySample],
    multi_vcpu_fingerprint_trajectory: &[ContractAMultiVcpuFingerprintSample],
    time_fingerprint: ContractATimeFingerprint,
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
    hasher.write_u64(time_trajectory.len() as u64);
    for sample in time_trajectory {
        hasher.write_u64(sample.aggregate_icount);
        hasher.write_u64(sample.virtual_time_ns);
    }
    hasher.write_u64(len_for_hash(multi_vcpu_fingerprint_trajectory.len()));
    for sample in multi_vcpu_fingerprint_trajectory {
        hasher.write_u64(sample.aggregate_icount);
        hasher.write_u64(len_for_hash(sample.vcpu_registers.len()));
        for register in &sample.vcpu_registers {
            hasher.write_u64(register.vcpu_id);
            hasher.write_bytes(&register.register_digest.bytes);
            hasher.write_u64(register.retired_instruction_count);
        }
        hasher.write_u64(sample.rr_cursor.current_vcpu);
        hasher.write_u64(sample.rr_cursor.position_in_quantum);
        hasher.write_u64(sample.rr_cursor.quantum_remaining);
        hasher.write_u64(sample.rr_cursor.rr_switch_quantum);
        hasher.write_bytes(&sample.sample_digest.bytes);
    }
    time_fingerprint.write_hash_material(&mut hasher);
    hasher.finish()
}
