//! Closed parameter schemas for node and QEMU-backed effects.
//!
//! Every destructive mutation identifies concrete architecture or memory state
//! and therefore requires before/after replay evidence from the live backend.
//! Sensor device effects are deliberately absent because current QEMU lacks the
//! required production devices.

use super::{
    BoundedCount, ByteRange, EffectKind, ExactRatio, FaultContractError, FaultObjectId, HexBytes,
    ObjectIdSet, PositiveU64,
};

/// Node lifecycle transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum NodeLifecycleTransition {
    /// Begin or retry boot.
    Boot,
    /// Crash the running node.
    Crash,
    /// Reset the node.
    Reset,
    /// Remove power.
    PowerOff,
    /// Restore power and boot.
    PowerCycle,
    /// Enter a permanent failed state.
    PermanentFailure,
}

/// Retention policy for volatile node or device state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatePolicy {
    /// Preserve the named state.
    Preserve,
    /// Clear the named state.
    Clear,
    /// Reinitialize through the production device's reset semantics.
    DeviceReset,
}

/// Scope of a progress hang.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum NodeHangScope {
    /// Stop progress on every vCPU and device scheduler for the node.
    Node,
    /// Stop progress on the named vCPU set.
    Vcpus(ObjectIdSet),
    /// Stop progress in the named production device.
    Device(FaultObjectId),
}

/// Requested vCPU run state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum VcpuState {
    /// The vCPU participates in scheduling.
    Online,
    /// The vCPU is removed from scheduling.
    Offline,
    /// The vCPU remains present but makes no progress.
    Stalled,
}

/// Register-value mutation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum RegisterMutation {
    /// XOR selected bits once or at each selected opportunity.
    BitFlip {
        /// Nonempty hexadecimal mask.
        mask: HexBytes,
    },
    /// Forces selected bits to a declared value while active.
    Stuck {
        /// Nonempty selected-bit mask.
        mask: HexBytes,
        /// Replacement values under the mask.
        value: HexBytes,
    },
    /// Replaces the complete selected range.
    Replace {
        /// Exact replacement bytes.
        value: HexBytes,
    },
}

/// Instruction-level mutation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum InstructionMutation {
    /// Applies a typed transform to a decoded destination or result.
    ResultCorrupt {
        /// Destination/result selector in the architecture registry.
        destination: FaultObjectId,
        /// Typed result transform.
        transform: FaultObjectId,
    },
    /// Skips the selected instruction under architecture-defined PC semantics.
    Skip,
    /// Replays the selected instruction a bounded number of times.
    Replay {
        /// Additional execution count.
        count: BoundedCount,
    },
}

/// Interrupt-delivery mutation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum InterruptMutation {
    /// Suppresses the selected delivery.
    Drop,
    /// Delays delivery by a positive duration.
    Delay {
        /// Added virtual delay.
        delay_nanos: PositiveU64,
    },
    /// Produces bounded additional deliveries.
    Duplicate {
        /// Number of additional deliveries.
        copies: BoundedCount,
        /// Gap between deliveries.
        gap_nanos: u64,
    },
    /// Replaces the vector or interrupt type.
    Replace {
        /// Replacement architecture vector.
        vector: u32,
    },
}

/// Atomic memory mutation at a safe boundary.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum MemoryMutationKind {
    /// XORs the selected range with a repeated mask.
    BitFlip {
        /// Nonempty XOR mask.
        mask: HexBytes,
    },
    /// Replaces the selected range with exact bytes.
    Replace {
        /// Exact replacement bytes.
        bytes: HexBytes,
    },
}

/// Persistent or per-access memory transform.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum MemoryAccessMutation {
    /// Forces selected bits during reads and writes.
    Stuck {
        /// Selected-bit mask.
        mask: HexBytes,
        /// Forced values under the mask.
        value: HexBytes,
    },
    /// Corrupts returned read bytes.
    ReadCorrupt {
        /// XOR mask applied to returned bytes.
        mask: HexBytes,
    },
    /// Acknowledges but suppresses selected stores.
    LostWrite,
    /// Applies a declared strict subset of store bytes.
    TornWrite {
        /// Registered deterministic byte selector.
        selector: FaultObjectId,
    },
    /// Produces an architecture-specific poison outcome.
    Poison {
        /// Registered poison/syndrome policy.
        policy: FaultObjectId,
    },
}

/// Memory ECC result class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum MemoryEccKind {
    /// The platform reports and corrects the error.
    Corrected,
    /// The platform reports an uncorrectable error.
    Uncorrectable,
}

/// Stateful memory-region failure process.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum MemoryRegionKind {
    /// Every selected access fails under the declared outcome.
    Failed,
    /// Bits decay according to time and environmental inputs.
    Retention,
    /// Aggressor accesses disturb declared victim rows.
    Rowhammer,
}

/// Clock transform family.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum ClockMutation {
    /// Adds a signed nanosecond offset.
    Offset {
        /// Signed offset in virtual nanoseconds.
        offset_nanos: i64,
    },
    /// Multiplies elapsed time by an exact positive ratio.
    Drift {
        /// Exact clock-rate ratio.
        ratio: ExactRatio,
    },
    /// Applies a signed discontinuous step.
    Jump {
        /// Signed step in nanoseconds.
        delta_nanos: i64,
    },
    /// Holds reads at one declared value.
    Freeze {
        /// Frozen clock value in nanoseconds.
        value_nanos: u64,
    },
    /// Adds keyed bounded per-read jitter.
    Jitter {
        /// Maximum absolute jitter.
        maximum_nanos: PositiveU64,
        /// Registered integer distribution lookup.
        distribution: FaultObjectId,
    },
    /// Evolves correlated rate/offset wander.
    Wander {
        /// Registered bounded wander process.
        process: FaultObjectId,
    },
}

/// Accelerator lifecycle transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum AcceleratorTransition {
    /// Remove the device from enumeration.
    Disappear,
    /// Reset device, queues, and declared memory.
    Reset,
    /// Restore enumeration and initialize the device.
    Reconnect,
}

/// Typed parameters for every executable node/QEMU effect kind.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum NodeEffectSpecification {
    /// Node lifecycle transition.
    Lifecycle {
        /// Requested transition.
        transition: NodeLifecycleTransition,
        /// Downtime before completion.
        downtime_nanos: u64,
        /// Boot/restart policy.
        boot_policy: FaultObjectId,
        /// Volatile node-state policy.
        volatile_state_policy: NodeStatePolicy,
        /// Device-state policy.
        device_state_policy: NodeStatePolicy,
    },
    /// Persistent node, vCPU, or device hang.
    Hang {
        /// Hang scope.
        scope: NodeHangScope,
        /// Recovery event identity.
        recovery_event: FaultObjectId,
        /// Registered watchdog policy.
        watchdog_policy: FaultObjectId,
    },
    /// Rational vCPU service capacity.
    CpuService {
        /// Selected vCPU identities.
        vcpus: ObjectIdSet,
        /// Exact positive capacity ratio.
        capacity: ExactRatio,
        /// Positive scheduling quantum.
        quantum_instructions: PositiveU64,
        /// Registered deterministic service rule.
        service_rule: FaultObjectId,
    },
    /// vCPU online, offline, or stalled transition.
    VcpuState {
        /// Requested state.
        state: VcpuState,
        /// Recovery event, when the state is not online.
        recovery_event: Option<FaultObjectId>,
    },
    /// Register bit-range transform.
    RegisterTransform {
        /// Architecture register identity.
        register: FaultObjectId,
        /// First selected bit.
        first_bit: u16,
        /// Positive selected bit count.
        bit_count: BoundedCount,
        /// Typed mutation.
        mutation: RegisterMutation,
        /// Registered occurrence selector.
        occurrence: FaultObjectId,
    },
    /// Instruction result corruption, skip, or replay.
    InstructionTransform {
        /// Program-counter/TB/instruction selector.
        selector: FaultObjectId,
        /// Typed instruction mutation.
        mutation: InstructionMutation,
    },
    /// Architecture-specific exception or hardware error.
    CpuException {
        /// Architecture contract identity.
        architecture: FaultObjectId,
        /// Exception kind or vector identity.
        exception: FaultObjectId,
        /// Typed syndrome/error-field artifact.
        error_fields: FaultObjectId,
    },
    /// Interrupt drop, delay, duplicate, or replacement.
    InterruptDisposition {
        /// Typed interrupt mutation.
        mutation: InterruptMutation,
    },
    /// Bounded interrupt storm.
    InterruptStorm {
        /// Interrupt source identity.
        source: FaultObjectId,
        /// Architecture vector.
        vector: u32,
        /// Positive period.
        period_nanos: PositiveU64,
        /// Events in each burst.
        burst: BoundedCount,
        /// Total event count.
        count: BoundedCount,
        /// Registered routing policy.
        routing: FaultObjectId,
    },
    /// Atomic memory mutation.
    MemoryMutation {
        /// Address-space identity.
        address_space: FaultObjectId,
        /// Resolved byte range.
        range: ByteRange,
        /// Typed mutation.
        mutation: MemoryMutationKind,
        /// Registered atomicity rule.
        atomicity: FaultObjectId,
    },
    /// Persistent or per-access memory transform.
    MemoryAccessTransform {
        /// Resolved byte range.
        range: ByteRange,
        /// Typed access mutation.
        mutation: MemoryAccessMutation,
        /// Registered access selector.
        occurrence: FaultObjectId,
    },
    /// Corrected or uncorrectable ECC event.
    MemoryEccEvent {
        /// ECC result class.
        kind: MemoryEccKind,
        /// Resolved address.
        address: u64,
        /// Architecture syndrome.
        syndrome: u64,
        /// Memory bank identity.
        bank: FaultObjectId,
        /// Memory channel identity.
        channel: FaultObjectId,
        /// Memory rank identity.
        rank: FaultObjectId,
        /// Registered guest-visible platform outcome.
        guest_visibility: FaultObjectId,
    },
    /// Stateful region failure, retention, or rowhammer model.
    MemoryRegionState {
        /// Resolved byte range.
        range: ByteRange,
        /// Region process kind.
        kind: MemoryRegionKind,
        /// Registered threshold/decay/access-pattern model.
        process: FaultObjectId,
    },
    /// Memory latency and service constraints.
    MemoryService {
        /// Added access latency.
        latency_nanos: u64,
        /// Optional positive byte rate.
        bandwidth_bytes_per_second: Option<PositiveU64>,
        /// Optional positive operation service rate.
        operations_per_second: Option<PositiveU64>,
        /// Registered sharing scope.
        sharing_scope: FaultObjectId,
    },
    /// Guest clock transform.
    ClockTransform {
        /// Source clock identity.
        source: FaultObjectId,
        /// Typed transform.
        mutation: ClockMutation,
        /// Registered monotonicity policy.
        monotonicity: FaultObjectId,
    },
    /// Guest clock failure, fallback, or synchronization state.
    ClockSourceState {
        /// Candidate source identities.
        sources: ObjectIdSet,
        /// Registered failure/fallback transition.
        transition: FaultObjectId,
        /// Registered synchronization correction and rate policy.
        synchronization_policy: FaultObjectId,
    },
    /// Accelerator disappearance, reset, or reconnect.
    AcceleratorLifecycle {
        /// Accelerator identity.
        device: FaultObjectId,
        /// Requested transition.
        transition: AcceleratorTransition,
        /// Pending queue policy.
        queue_policy: NodeStatePolicy,
        /// Attached memory policy.
        memory_policy: NodeStatePolicy,
    },
    /// Accelerator result field or buffer transform.
    AcceleratorResultTransform {
        /// API/device job selector.
        job_selector: FaultObjectId,
        /// Registered typed result transform.
        transform: FaultObjectId,
    },
    /// Accelerator-memory ECC or data transform event.
    AcceleratorMemoryEvent {
        /// Device-memory byte range.
        range: ByteRange,
        /// Optional ECC result.
        ecc: Option<MemoryEccKind>,
        /// Optional architecture/device syndrome.
        syndrome: Option<u64>,
        /// Optional registered data transform.
        transform: Option<FaultObjectId>,
    },
    /// Accelerator compute, memory, thermal, or power service cap.
    AcceleratorService {
        /// Exact positive compute-capacity ratio.
        capacity: ExactRatio,
        /// Optional memory byte-rate cap.
        memory_bytes_per_second: Option<PositiveU64>,
        /// Optional job service-rate cap.
        jobs_per_second: Option<PositiveU64>,
        /// Registered thermal and power metadata.
        thermal_power: FaultObjectId,
    },
}

impl NodeEffectSpecification {
    /// Returns the exact closed registry kind for these parameters.
    #[must_use]
    pub const fn kind(&self) -> EffectKind {
        match self {
            Self::Lifecycle { .. } => EffectKind::NodeLifecycle,
            Self::Hang { .. } => EffectKind::NodeHang,
            Self::CpuService { .. } => EffectKind::CpuService,
            Self::VcpuState { .. } => EffectKind::CpuVcpuState,
            Self::RegisterTransform { .. } => EffectKind::CpuRegisterTransform,
            Self::InstructionTransform { .. } => EffectKind::CpuInstructionTransform,
            Self::CpuException { .. } => EffectKind::CpuException,
            Self::InterruptDisposition { .. } => EffectKind::InterruptDisposition,
            Self::InterruptStorm { .. } => EffectKind::InterruptStorm,
            Self::MemoryMutation { .. } => EffectKind::MemoryMutation,
            Self::MemoryAccessTransform { .. } => EffectKind::MemoryAccessTransform,
            Self::MemoryEccEvent { .. } => EffectKind::MemoryEccEvent,
            Self::MemoryRegionState { .. } => EffectKind::MemoryRegionState,
            Self::MemoryService { .. } => EffectKind::MemoryService,
            Self::ClockTransform { .. } => EffectKind::ClockTransform,
            Self::ClockSourceState { .. } => EffectKind::ClockSourceState,
            Self::AcceleratorLifecycle { .. } => EffectKind::AcceleratorLifecycle,
            Self::AcceleratorResultTransform { .. } => EffectKind::AcceleratorResultTransform,
            Self::AcceleratorMemoryEvent { .. } => EffectKind::AcceleratorMemoryEvent,
            Self::AcceleratorService { .. } => EffectKind::AcceleratorService,
        }
    }

    /// Validates cross-field node and QEMU effect invariants.
    ///
    /// # Errors
    ///
    /// Returns [`FaultContractError::InvalidEffectParameters`] for non-positive
    /// capacity ratios, mismatched byte widths, invalid bit ranges, or an
    /// accelerator memory event without exactly one typed outcome.
    pub fn validate(&self) -> Result<(), FaultContractError> {
        let invalid = || FaultContractError::InvalidEffectParameters {
            effect: self.kind(),
        };
        match self {
            Self::CpuService { capacity, .. } | Self::AcceleratorService { capacity, .. }
                if capacity.numerator() <= 0 =>
            {
                Err(invalid())
            }
            Self::RegisterTransform {
                first_bit,
                bit_count,
                mutation,
                ..
            } => {
                let selected_bytes = usize::try_from(bit_count.get().div_ceil(8));
                let end_valid = u32::from(*first_bit)
                    .checked_add(bit_count.get())
                    .is_some_and(|end| end <= 65_536);
                let bytes_match = match mutation {
                    RegisterMutation::BitFlip { mask }
                    | RegisterMutation::Replace { value: mask } => {
                        selected_bytes == Ok(mask.decoded_len())
                    }
                    RegisterMutation::Stuck { mask, value } => {
                        selected_bytes == Ok(mask.decoded_len())
                            && mask.decoded_len() == value.decoded_len()
                    }
                };
                if end_valid && bytes_match {
                    Ok(())
                } else {
                    Err(invalid())
                }
            }
            Self::MemoryMutation {
                range, mutation, ..
            } => {
                let exact = match mutation {
                    MemoryMutationKind::BitFlip { mask } => mask.decoded_len() > 0,
                    MemoryMutationKind::Replace { bytes } => {
                        u64::try_from(bytes.decoded_len()) == Ok(range.length())
                    }
                };
                if exact { Ok(()) } else { Err(invalid()) }
            }
            Self::AcceleratorMemoryEvent {
                ecc,
                syndrome,
                transform,
                ..
            } => {
                let ecc_valid = ecc.is_some() && transform.is_none();
                let transform_valid = ecc.is_none() && syndrome.is_none() && transform.is_some();
                if (ecc_valid || transform_valid) && (!ecc_valid || syndrome.is_some()) {
                    Ok(())
                } else {
                    Err(invalid())
                }
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::CountLimit;

    #[test]
    fn nonpositive_cpu_capacity_is_rejected() {
        let capacity = match ExactRatio::new(0, 1) {
            Ok(value) => value,
            Err(error) => panic!("zero ratio is canonical: {error}"),
        };
        let vcpu = match FaultObjectId::parse("vcpu-zero") {
            Ok(value) => value,
            Err(error) => panic!("test ID must be valid: {error}"),
        };
        let vcpus = match ObjectIdSet::new(vec![vcpu]) {
            Ok(value) => value,
            Err(error) => panic!("test ID set must be valid: {error}"),
        };
        let quantum = match PositiveU64::new("quantum_instructions", 1) {
            Ok(value) => value,
            Err(error) => panic!("test quantum must be valid: {error}"),
        };
        let rule = match FaultObjectId::parse("round-robin") {
            Ok(value) => value,
            Err(error) => panic!("test ID must be valid: {error}"),
        };
        let effect = NodeEffectSpecification::CpuService {
            vcpus,
            capacity,
            quantum_instructions: quantum,
            service_rule: rule,
        };
        assert_eq!(effect.kind(), EffectKind::CpuService);
        assert!(effect.validate().is_err());
    }

    #[test]
    fn register_transform_requires_exact_selected_width() {
        let register = match FaultObjectId::parse("rax") {
            Ok(value) => value,
            Err(error) => panic!("test register must be valid: {error}"),
        };
        let bit_count = match BoundedCount::new(CountLimit::RegisterBits, 64) {
            Ok(value) => value,
            Err(error) => panic!("test bit count must be valid: {error}"),
        };
        let short_mask = match HexBytes::parse("ff", 8) {
            Ok(value) => value,
            Err(error) => panic!("test mask must be valid: {error}"),
        };
        let occurrence = match FaultObjectId::parse("every-match") {
            Ok(value) => value,
            Err(error) => panic!("test occurrence must be valid: {error}"),
        };
        let effect = NodeEffectSpecification::RegisterTransform {
            register,
            first_bit: 0,
            bit_count,
            mutation: RegisterMutation::BitFlip { mask: short_mask },
            occurrence,
        };
        assert!(effect.validate().is_err());
    }
}
