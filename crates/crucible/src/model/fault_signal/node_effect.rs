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

/// Exhaustive behavior for a node boot or restart attempt.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum NodeBootPolicy {
    /// Releases the realized machine immediately and requires no guest marker.
    Immediate,
    /// Requires a declared guest-ready marker and applies a bounded retry rule.
    RequireReady {
        /// Stable ready-marker identity observed by the host/QEMU boundary.
        ready_marker: FaultObjectId,
        /// Maximum number of boot attempts, including the first attempt.
        maximum_attempts: BoundedCount,
        /// Virtual delay between failed attempts.
        retry_delay_nanos: u64,
        /// Terminal transition after the final failed attempt.
        exhausted: NodeLifecycleTransition,
    },
}

/// Deterministic watchdog behavior while a node or subcomponent is hung.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum NodeWatchdogPolicy {
    /// Leaves recovery entirely to the declared recovery event.
    Disabled,
    /// Applies a lifecycle transition after an exact virtual timeout.
    TransitionAfter {
        /// Positive virtual timeout from entry into the hung state.
        timeout_nanos: PositiveU64,
        /// Lifecycle transition performed at timeout.
        transition: NodeLifecycleTransition,
    },
}

/// Deterministic vCPU capacity accounting discipline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum CpuServiceDiscipline {
    /// Allows unused service to be consumed by another eligible selected vCPU.
    WorkConserving,
    /// Enforces each selected vCPU's cap independently without borrowing.
    StrictCap,
}

/// Closed opportunity-selection policy evaluated by QEMU.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum NodeOccurrencePolicy {
    /// Selects every matching opportunity.
    Every,
    /// Selects a bounded arithmetic sequence of one-based match ordinals.
    Periodic {
        /// First one-based matching ordinal selected.
        first: PositiveU64,
        /// Positive distance between selected ordinals.
        period: PositiveU64,
        /// Maximum number of selected ordinals.
        count: BoundedCount,
    },
}

/// Scope of a progress hang.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum NodeHangScope {
    /// Stop progress on every vCPU and device scheduler for the node.
    Node,
    /// Stop progress on the named vCPU set.
    Vcpus(Vec<u32>),
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
        /// Fully resolved destination and value mutation.
        transform: InstructionResultTransform,
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

/// Address space used to resolve an exact-boundary memory mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAddressSpace {
    /// Treats the supplied address as a guest physical address.
    GuestPhysical,
    /// Translates the supplied address in the selected vCPU context.
    GuestVirtual,
}

/// Atomic commit behavior for an exact-boundary memory mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum MemoryMutationAtomicity {
    /// Resolves and validates every byte before changing any byte.
    AllOrNothing,
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
        /// Repeated nonzero byte-selection mask; selected bits are committed.
        selector: HexBytes,
    },
    /// Produces an architecture-specific poison outcome.
    Poison {
        /// Closed guest-visible poison behavior.
        policy: MemoryPoisonPolicy,
    },
}

/// Guest-visible outcome of a poisoned memory access.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum MemoryPoisonPolicy {
    /// Returns a memory transaction error without exposing bytes.
    AccessError,
    /// Returns corrected bytes after applying the repeated XOR mask.
    Corrected {
        /// Repeated correction/corruption mask applied before return.
        xor_mask: HexBytes,
    },
    /// Raises one architecture exception with complete numeric fields.
    Exception {
        /// Closed exception contract.
        exception: NodeException,
    },
}

/// QEMU memory-access classes selected by one rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryAccessClasses {
    /// Selects instruction fetches.
    pub fetch: bool,
    /// Selects CPU data loads.
    pub cpu_load: bool,
    /// Selects CPU data stores.
    pub cpu_store: bool,
    /// Selects device DMA reads.
    pub dma_read: bool,
    /// Selects device DMA writes.
    pub dma_write: bool,
    /// Selects implicit page-table descriptor reads performed by a vCPU MMU walk.
    pub page_table_walk: bool,
}

/// Architecture family for an injected CPU exception.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum NodeExceptionArchitecture {
    /// x86-64 exception entry.
    X86_64,
    /// AArch64 exception entry.
    Aarch64,
}

/// Exact architecture exception injected before or after an instruction.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeException {
    /// Architecture whose entry machinery validates the remaining fields.
    pub architecture: NodeExceptionArchitecture,
    /// Architecture vector or exception class number.
    pub vector: u32,
    /// Architecture syndrome or error code.
    pub syndrome: u64,
    /// Optional guest fault address.
    pub fault_address: Option<u64>,
    /// Injects before the selected instruction when true, after it otherwise.
    pub before_instruction: bool,
    /// Declares whether ordinary architecture masking may defer delivery.
    pub maskable: bool,
    /// Complete architecture record fields, or ordinary exception entry.
    pub record: NodeExceptionRecord,
}

/// Architecture-specific record state accompanying an exception.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum NodeExceptionRecord {
    /// Uses ordinary architecture exception entry without a hardware record.
    ArchitectureDefault,
    /// Publishes complete x86 machine-check bank and global status.
    X86MachineCheck {
        /// Numeric machine-check bank.
        bank: u32,
        /// IA32_MCi_STATUS value validated against the manifest mask.
        status: u64,
        /// IA32_MCG_STATUS value validated against the manifest mask.
        global_status: u64,
        /// Optional IA32_MCi_ADDR value.
        address: Option<u64>,
        /// Optional IA32_MCi_MISC value.
        misc: Option<u64>,
        /// Marks a corrected rather than uncorrectable record.
        corrected: bool,
    },
    /// Publishes complete AArch64 RAS syndrome and delivery state.
    Aarch64Ras {
        /// Exact ESR_ELx value validated against the manifest mask.
        esr: u64,
        /// Optional FAR_ELx value.
        far: Option<u64>,
        /// Optional DISR_EL1 value for deferred/asynchronous delivery.
        disr: Option<u64>,
        /// Selects asynchronous SError rather than synchronous abort entry.
        asynchronous: bool,
        /// Marks a corrected rather than uncorrectable record.
        corrected: bool,
    },
}

/// Exact instruction match contract used at the QEMU execution hook.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstructionSelector {
    /// Inclusive virtual-PC start.
    pub pc_start: u64,
    /// Positive byte length of the selected PC interval.
    pub pc_length: PositiveU64,
    /// Optional exact instruction bytes; an empty wildcard is not permitted.
    pub instruction_bytes: Option<HexBytes>,
    /// Optional stable decoded opcode/class number from the QEMU manifest.
    pub opcode_class: Option<u32>,
    /// Optional SHA-256 digest required of complete CPU, RAM, and device input state.
    pub input_state_sha256: Option<HexBytes>,
    /// Opportunity-selection policy within the matching stream.
    pub occurrence: NodeOccurrencePolicy,
}

/// Fully resolved instruction-result mutation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstructionResultTransform {
    /// Stable destination register identity from the architecture manifest.
    pub destination: FaultObjectId,
    /// Concrete value mutation applied after the instruction commits.
    pub mutation: RegisterMutation,
}

/// Deterministic interrupt routing for storms and delayed/duplicate delivery.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterruptRoutingPolicy {
    /// Ordered, nonempty set of destination vCPU IDs.
    pub target_vcpus: Vec<u32>,
    /// Architecture controller priority value.
    pub priority: u32,
    /// Retains controller pending state when a delivery is suppressed.
    pub retain_pending: bool,
}

/// Guest-visible platform reporting for one ECC event.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum MemoryEccVisibility {
    /// Records corrected telemetry without injecting an architecture event.
    TelemetryOnly,
    /// Injects the declared corrected-error interrupt.
    CorrectedInterrupt {
        /// Architecture vector.
        vector: u32,
    },
    /// Injects a complete architecture exception/error record.
    Exception(NodeException),
}

/// Complete state machine parameters for a failed/retention/rowhammer range.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum MemoryRegionProcess {
    /// Every selected access returns a declared poison outcome.
    Failed {
        /// Guest-visible access outcome.
        policy: MemoryPoisonPolicy,
    },
    /// Applies a repeated decay mask after each exact exposure interval.
    Retention {
        /// Positive virtual exposure interval.
        interval_nanos: PositiveU64,
        /// Repeated bits eligible to decay.
        decay_mask: HexBytes,
    },
    /// Disturbs explicitly adjacent rows after a bounded access threshold.
    Rowhammer {
        /// Positive bytes per modeled DRAM row.
        row_bytes: PositiveU64,
        /// Positive aggressor-access threshold.
        threshold: PositiveU64,
        /// Positive victim-row distance on either side of the aggressor.
        victim_distance: PositiveU64,
        /// Repeated victim-bit XOR mask.
        flip_mask: HexBytes,
    },
}

/// Sharing domain for a memory service curve.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum MemoryServiceScope {
    /// Shares capacity across the complete node.
    Node,
    /// Shares capacity only across the targeted range.
    Range,
    /// Shares capacity across one realized memory-controller identity.
    Controller(FaultObjectId),
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
        /// Behavior when the freeze rule is removed.
        release: ClockFreezeReleasePolicy,
    },
    /// Adds keyed bounded per-read jitter.
    Jitter {
        /// Maximum absolute jitter.
        maximum_nanos: PositiveU64,
        /// Nonempty ordered lookup table indexed by the keyed opportunity.
        distribution_nanos: Vec<i64>,
    },
    /// Evolves correlated rate/offset wander.
    Wander {
        /// Complete bounded deterministic wander process.
        process: ClockWanderProcess,
    },
}

/// Clock value behavior when a freeze contribution is removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum ClockFreezeReleasePolicy {
    /// Reanchors progression at the frozen value without a discontinuity.
    ResumeFromFrozen,
    /// Exposes the current unfrozen source value as an explicit jump.
    CatchUpJump,
}

/// Disposition of a timer made overdue by a clock transform.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum ClockOverdueTimerPolicy {
    /// Fires once at the transform boundary.
    FireAtBoundary,
    /// Drops the overdue occurrence.
    Drop,
    /// Advances a periodic timer to its first future source-domain deadline.
    ReschedulePeriodic,
}

/// Bounded deterministic clock-wander state evolution.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockWanderProcess {
    /// Positive virtual interval between state updates.
    pub step_nanos: PositiveU64,
    /// Maximum absolute offset from the transform anchor.
    pub maximum_offset_nanos: PositiveU64,
    /// Maximum absolute rate adjustment in parts per billion.
    pub maximum_rate_ppb: PositiveU64,
    /// Nonempty ordered signed increments selected by keyed opportunity.
    pub increments_ppb: Vec<i64>,
}

/// Handling of a transformed clock value that moves backward.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum ClockMonotonicityPolicy {
    /// Exposes backward values.
    AllowBackward,
    /// Clamps reads to the last exposed value.
    ClampMonotonic,
    /// Produces a guest-visible source error.
    FaultOnBackward,
}

/// Guest clock source state transition.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum ClockSourceTransition {
    /// Returns all selected sources to their normal state.
    Healthy,
    /// Marks selected sources degraded but readable.
    Degraded,
    /// Stops or errors selected sources without fallback.
    Failed {
        /// Guest-visible failure behavior.
        behavior: ClockFailureBehavior,
    },
    /// Replaces selected sources with one declared realized source.
    Fallback {
        /// Stable fallback source identity.
        source: FaultObjectId,
    },
}

/// Guest-visible behavior of a failed clock source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum ClockFailureBehavior {
    /// Holds the source at its last exposed value.
    Stop,
    /// Returns the source's architecture-defined unavailable/error result.
    ReadError,
}

/// Clock correction applied while entering or leaving fallback.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum ClockSynchronizationPolicy {
    /// Applies the complete correction as one explicit step.
    Step,
    /// Slews at an exact positive rate until within the declared threshold.
    Slew {
        /// Exact correction-rate multiplier.
        rate: ExactRatio,
        /// Positive completion threshold.
        threshold_nanos: PositiveU64,
    },
}

/// Accelerator job match coordinates understood by the realized device.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceleratorJobSelector {
    /// Stable manifest job-kind identity.
    pub job_kind: FaultObjectId,
    /// Optional exact queue ID.
    pub queue: Option<u32>,
    /// Opportunity selection within matching jobs.
    pub occurrence: NodeOccurrencePolicy,
}

/// Exact accelerator result-buffer transform.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceleratorResultMutation {
    /// Byte offset in the realized result schema or output buffer.
    pub offset: u64,
    /// Repeated selected-bit mask.
    pub mask: HexBytes,
    /// Replacement bits under the mask.
    pub value: HexBytes,
}

/// Canonical thermal/power metadata accompanying an accelerator service cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceleratorThermalPower {
    /// Modeled temperature in millikelvin.
    pub temperature_millikelvin: u64,
    /// Modeled power draw in milliwatts.
    pub power_milliwatts: u64,
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
        boot_policy: NodeBootPolicy,
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
        /// Closed watchdog policy.
        watchdog_policy: NodeWatchdogPolicy,
    },
    /// Rational vCPU service capacity.
    CpuService {
        /// Ordered, nonempty selected vCPU IDs.
        vcpus: Vec<u32>,
        /// Exact positive capacity ratio.
        capacity: ExactRatio,
        /// Positive scheduling quantum.
        quantum_instructions: PositiveU64,
        /// Deterministic service discipline.
        service_rule: CpuServiceDiscipline,
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
        /// Closed occurrence selector.
        occurrence: NodeOccurrencePolicy,
    },
    /// Instruction result corruption, skip, or replay.
    InstructionTransform {
        /// Program-counter/TB/instruction selector.
        selector: InstructionSelector,
        /// Typed instruction mutation.
        mutation: InstructionMutation,
    },
    /// Architecture-specific exception or hardware error.
    CpuException {
        /// Complete architecture exception contract.
        exception: NodeException,
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
        /// Closed routing policy.
        routing: InterruptRoutingPolicy,
    },
    /// Atomic memory mutation.
    MemoryMutation {
        /// Address space used to resolve the range.
        address_space: MemoryAddressSpace,
        /// Resolved byte range.
        range: ByteRange,
        /// Typed mutation.
        mutation: MemoryMutationKind,
        /// Atomic commit behavior.
        atomicity: MemoryMutationAtomicity,
    },
    /// Persistent or per-access memory transform.
    MemoryAccessTransform {
        /// Resolved byte range.
        range: ByteRange,
        /// Explicit CPU/fetch/DMA access classes selected by the rule.
        accesses: MemoryAccessClasses,
        /// Optional canonical device identity restricting DMA opportunities.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dma_device: Option<FaultObjectId>,
        /// Allows a torn-write rule to violate a supported atomic access.
        violate_atomicity: bool,
        /// Typed access mutation.
        mutation: MemoryAccessMutation,
        /// Closed access selector.
        occurrence: NodeOccurrencePolicy,
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
        /// Guest-visible platform outcome.
        guest_visibility: MemoryEccVisibility,
    },
    /// Stateful region failure, retention, or rowhammer model.
    MemoryRegionState {
        /// Resolved byte range.
        range: ByteRange,
        /// Region process kind.
        kind: MemoryRegionKind,
        /// Complete threshold, decay, or access-pattern model.
        process: MemoryRegionProcess,
    },
    /// Memory latency and service constraints.
    MemoryService {
        /// Added access latency.
        latency_nanos: u64,
        /// Optional positive byte rate.
        bandwidth_bytes_per_second: Option<PositiveU64>,
        /// Optional positive operation service rate.
        operations_per_second: Option<PositiveU64>,
        /// Closed sharing scope.
        sharing_scope: MemoryServiceScope,
    },
    /// Guest clock transform.
    ClockTransform {
        /// Source clock identity.
        source: FaultObjectId,
        /// Typed transform.
        mutation: ClockMutation,
        /// Closed monotonicity policy.
        monotonicity: ClockMonotonicityPolicy,
        /// Disposition of timers made overdue by the transform.
        overdue_timer_policy: ClockOverdueTimerPolicy,
    },
    /// Guest clock failure, fallback, or synchronization state.
    ClockSourceState {
        /// Candidate source identities.
        sources: ObjectIdSet,
        /// Closed failure or fallback transition.
        transition: ClockSourceTransition,
        /// Closed synchronization correction and rate policy.
        synchronization_policy: ClockSynchronizationPolicy,
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
        job_selector: AcceleratorJobSelector,
        /// Closed typed result transform.
        transform: AcceleratorResultMutation,
    },
    /// Accelerator-memory ECC or data transform event.
    AcceleratorMemoryEvent {
        /// Device-memory byte range.
        range: ByteRange,
        /// Optional ECC result.
        ecc: Option<MemoryEccKind>,
        /// Optional architecture/device syndrome.
        syndrome: Option<u64>,
        /// Optional exact data transform.
        transform: Option<HexBytes>,
    },
    /// Accelerator compute, memory, thermal, or power service cap.
    AcceleratorService {
        /// Exact positive compute-capacity ratio.
        capacity: ExactRatio,
        /// Optional memory byte-rate cap.
        memory_bytes_per_second: Option<PositiveU64>,
        /// Optional job service-rate cap.
        jobs_per_second: Option<PositiveU64>,
        /// Exact thermal and power metadata.
        thermal_power: AcceleratorThermalPower,
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
            Self::Lifecycle {
                transition,
                boot_policy: NodeBootPolicy::RequireReady { exhausted, .. },
                ..
            } if !matches!(
                transition,
                NodeLifecycleTransition::Boot
                    | NodeLifecycleTransition::Reset
                    | NodeLifecycleTransition::PowerCycle
            ) || !matches!(
                exhausted,
                NodeLifecycleTransition::Crash
                    | NodeLifecycleTransition::PowerOff
                    | NodeLifecycleTransition::PermanentFailure
            ) =>
            {
                Err(invalid())
            }
            Self::Lifecycle {
                volatile_state_policy: NodeStatePolicy::DeviceReset,
                ..
            } => Err(invalid()),
            Self::Hang {
                scope: NodeHangScope::Vcpus(vcpus),
                ..
            } if !vcpu_set_valid(vcpus) => Err(invalid()),
            Self::CpuService { vcpus, .. } if !vcpu_set_valid(vcpus) => Err(invalid()),
            Self::CpuService { capacity, .. } | Self::AcceleratorService { capacity, .. }
                if !capacity_ratio_valid(*capacity) =>
            {
                Err(invalid())
            }
            Self::VcpuState {
                state: VcpuState::Online,
                recovery_event: Some(_),
            }
            | Self::VcpuState {
                state: VcpuState::Offline | VcpuState::Stalled,
                recovery_event: None,
            } => Err(invalid()),
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
                            && (!matches!(mutation, RegisterMutation::BitFlip { .. })
                                || hex_has_nonzero(mask))
                    }
                    RegisterMutation::Stuck { mask, value } => {
                        selected_bytes == Ok(mask.decoded_len())
                            && mask.decoded_len() == value.decoded_len()
                            && hex_has_nonzero(mask)
                    }
                };
                if end_valid && bytes_match {
                    Ok(())
                } else {
                    Err(invalid())
                }
            }
            Self::InstructionTransform {
                mutation: InstructionMutation::Replay { count },
                ..
            } if count.get() > 256 => Err(invalid()),
            Self::InstructionTransform { selector, mutation } => {
                let selector_valid = selector
                    .pc_start
                    .checked_add(selector.pc_length.get())
                    .is_some()
                    && selector
                        .instruction_bytes
                        .as_ref()
                        .is_none_or(|bytes| bytes.decoded_len() <= 32);
                let selector_valid = selector_valid
                    && selector
                        .input_state_sha256
                        .as_ref()
                        .is_none_or(|digest| digest.decoded_len() == 32);
                let transform_valid = match mutation {
                    InstructionMutation::ResultCorrupt { transform } => {
                        register_mutation_lengths_match(&transform.mutation)
                    }
                    InstructionMutation::Skip | InstructionMutation::Replay { .. } => true,
                };
                if selector_valid && transform_valid {
                    Ok(())
                } else {
                    Err(invalid())
                }
            }
            Self::CpuException { exception } if !exception_valid(exception) => Err(invalid()),
            Self::InterruptDisposition {
                mutation: InterruptMutation::Duplicate { copies, gap_nanos },
            } if copies.get() > 256 || gap_nanos.checked_mul(u64::from(copies.get())).is_none() => {
                Err(invalid())
            }
            Self::InterruptStorm { routing, .. }
                if routing.target_vcpus.is_empty()
                    || routing.target_vcpus.len() > 4_096
                    || routing
                        .target_vcpus
                        .windows(2)
                        .any(|pair| pair[0] >= pair[1]) =>
            {
                Err(invalid())
            }
            Self::MemoryMutation {
                range, mutation, ..
            } => {
                let exact = match mutation {
                    MemoryMutationKind::BitFlip { mask } => hex_has_nonzero(mask),
                    MemoryMutationKind::Replace { bytes } => {
                        u64::try_from(bytes.decoded_len()) == Ok(range.length())
                    }
                };
                if exact { Ok(()) } else { Err(invalid()) }
            }
            Self::MemoryAccessTransform {
                accesses,
                dma_device,
                violate_atomicity,
                mutation,
                ..
            } => {
                let access_selected = accesses.fetch
                    || accesses.cpu_load
                    || accesses.cpu_store
                    || accesses.dma_read
                    || accesses.dma_write
                    || accesses.page_table_walk;
                let mutation_valid = match mutation {
                    MemoryAccessMutation::Stuck { mask, value } => {
                        hex_has_nonzero(mask) && mask.decoded_len() == value.decoded_len()
                    }
                    MemoryAccessMutation::ReadCorrupt { mask } => hex_has_nonzero(mask),
                    MemoryAccessMutation::LostWrite => accesses.cpu_store || accesses.dma_write,
                    MemoryAccessMutation::TornWrite { selector } => {
                        let selector = selector.decode();
                        (accesses.cpu_store || accesses.dma_write)
                            && selector.iter().any(|byte| *byte != 0)
                            && selector.iter().any(|byte| *byte != u8::MAX)
                    }
                    MemoryAccessMutation::Poison {
                        policy: MemoryPoisonPolicy::Corrected { xor_mask },
                    } => hex_has_nonzero(xor_mask),
                    MemoryAccessMutation::Poison {
                        policy: MemoryPoisonPolicy::Exception { exception },
                    } => exception_valid(exception),
                    MemoryAccessMutation::Poison {
                        policy: MemoryPoisonPolicy::AccessError,
                    } => true,
                };
                let access_compatible = match mutation {
                    MemoryAccessMutation::ReadCorrupt { .. } => {
                        (accesses.fetch
                            || accesses.cpu_load
                            || accesses.dma_read
                            || accesses.page_table_walk)
                            && !accesses.cpu_store
                            && !accesses.dma_write
                    }
                    MemoryAccessMutation::LostWrite | MemoryAccessMutation::TornWrite { .. } => {
                        (accesses.cpu_store || accesses.dma_write)
                            && !accesses.fetch
                            && !accesses.cpu_load
                            && !accesses.dma_read
                    }
                    MemoryAccessMutation::Poison {
                        policy: MemoryPoisonPolicy::Corrected { .. },
                    } => {
                        (accesses.fetch
                            || accesses.cpu_load
                            || accesses.dma_read
                            || accesses.page_table_walk)
                            && !accesses.cpu_store
                            && !accesses.dma_write
                    }
                    MemoryAccessMutation::Poison {
                        policy: MemoryPoisonPolicy::Exception { .. },
                    } => {
                        (accesses.fetch || accesses.cpu_load || accesses.cpu_store)
                            && !accesses.dma_read
                            && !accesses.dma_write
                            && !accesses.page_table_walk
                    }
                    _ => true,
                };
                let atomicity_valid = !*violate_atomicity
                    || matches!(mutation, MemoryAccessMutation::TornWrite { .. });
                let dma_device_valid = dma_device.is_none()
                    || ((!accesses.fetch
                        && !accesses.cpu_load
                        && !accesses.cpu_store
                        && !accesses.page_table_walk)
                        && (accesses.dma_read || accesses.dma_write));
                if access_selected
                    && access_compatible
                    && mutation_valid
                    && atomicity_valid
                    && dma_device_valid
                {
                    Ok(())
                } else {
                    Err(invalid())
                }
            }
            Self::MemoryEccEvent {
                guest_visibility: MemoryEccVisibility::Exception(exception),
                ..
            } if !exception_valid(exception) => Err(invalid()),
            Self::MemoryRegionState { kind, process, .. }
                if !matches!(
                    (kind, process),
                    (MemoryRegionKind::Failed, MemoryRegionProcess::Failed { .. })
                        | (
                            MemoryRegionKind::Retention,
                            MemoryRegionProcess::Retention { .. }
                        )
                        | (
                            MemoryRegionKind::Rowhammer,
                            MemoryRegionProcess::Rowhammer { .. }
                        )
                ) =>
            {
                Err(invalid())
            }
            Self::MemoryRegionState {
                process:
                    MemoryRegionProcess::Failed {
                        policy: MemoryPoisonPolicy::Corrected { .. },
                    },
                ..
            } => Err(invalid()),
            Self::MemoryRegionState {
                process:
                    MemoryRegionProcess::Failed {
                        policy: MemoryPoisonPolicy::Exception { exception },
                    },
                ..
            } if !exception_valid(exception) => Err(invalid()),
            Self::MemoryRegionState {
                process: MemoryRegionProcess::Retention { decay_mask, .. },
                ..
            } if !hex_has_nonzero(decay_mask) => Err(invalid()),
            Self::MemoryRegionState {
                process: MemoryRegionProcess::Rowhammer { flip_mask, .. },
                ..
            } if !hex_has_nonzero(flip_mask) => Err(invalid()),
            Self::MemoryService {
                latency_nanos: 0,
                bandwidth_bytes_per_second: None,
                operations_per_second: None,
                ..
            } => Err(invalid()),
            Self::ClockTransform {
                mutation: ClockMutation::Drift { ratio },
                ..
            } if ratio.numerator() <= 0 => Err(invalid()),
            Self::ClockTransform {
                mutation:
                    ClockMutation::Jitter {
                        maximum_nanos,
                        distribution_nanos,
                    },
                ..
            } if distribution_nanos.is_empty()
                || distribution_nanos.len() > 4_096
                || distribution_nanos
                    .iter()
                    .any(|value| value.unsigned_abs() > maximum_nanos.get()) =>
            {
                Err(invalid())
            }
            Self::ClockTransform {
                mutation: ClockMutation::Wander { process },
                ..
            } if process.increments_ppb.is_empty()
                || process.increments_ppb.len() > 4_096
                || process
                    .increments_ppb
                    .iter()
                    .any(|value| value.unsigned_abs() > process.maximum_rate_ppb.get()) =>
            {
                Err(invalid())
            }
            Self::ClockSourceState {
                synchronization_policy: ClockSynchronizationPolicy::Slew { rate, .. },
                ..
            } if rate.numerator() <= 0 => Err(invalid()),
            Self::AcceleratorResultTransform { transform, .. }
                if transform.mask.decoded_len() == 0
                    || !hex_has_nonzero(&transform.mask)
                    || transform.mask.decoded_len() != transform.value.decoded_len() =>
            {
                Err(invalid())
            }
            Self::AcceleratorMemoryEvent {
                ecc,
                syndrome,
                transform,
                ..
            } => {
                let ecc_valid = ecc.is_some() && transform.is_none();
                let transform_valid = ecc.is_none()
                    && syndrome.is_none()
                    && transform.as_ref().is_some_and(hex_has_nonzero);
                if (ecc_valid || transform_valid) && (!ecc_valid || syndrome.is_some()) {
                    Ok(())
                } else {
                    Err(invalid())
                }
            }
            Self::AcceleratorService { thermal_power, .. }
                if thermal_power.temperature_millikelvin == 0
                    || thermal_power.power_milliwatts == 0 =>
            {
                Err(invalid())
            }
            _ => Ok(()),
        }
    }
}

fn register_mutation_lengths_match(mutation: &RegisterMutation) -> bool {
    match mutation {
        RegisterMutation::BitFlip { mask } => hex_has_nonzero(mask),
        RegisterMutation::Stuck { mask, value } => {
            hex_has_nonzero(mask) && mask.decoded_len() == value.decoded_len()
        }
        RegisterMutation::Replace { value } => value.decoded_len() > 0,
    }
}

fn hex_has_nonzero(value: &HexBytes) -> bool {
    value.decode().iter().any(|byte| *byte != 0)
}

fn exception_valid(exception: &NodeException) -> bool {
    let vector_valid = match exception.architecture {
        NodeExceptionArchitecture::X86_64 => exception.vector <= 255,
        NodeExceptionArchitecture::Aarch64 => exception.vector <= 0x3ff,
    };
    let record_valid = match (&exception.architecture, &exception.record) {
        (_, NodeExceptionRecord::ArchitectureDefault) => true,
        (
            NodeExceptionArchitecture::X86_64,
            NodeExceptionRecord::X86MachineCheck {
                status, address, ..
            },
        ) => exception.vector == 18 && *status != 0 && exception.fault_address == *address,
        (
            NodeExceptionArchitecture::Aarch64,
            NodeExceptionRecord::Aarch64Ras {
                esr,
                far,
                asynchronous,
                disr,
                ..
            },
        ) => {
            exception.syndrome == *esr
                && exception.fault_address == *far
                && (!*asynchronous || disr.is_some())
        }
        _ => false,
    };
    vector_valid && record_valid
}

fn vcpu_set_valid(vcpus: &[u32]) -> bool {
    !vcpus.is_empty() && vcpus.len() <= 4_096 && !vcpus.windows(2).any(|pair| pair[0] >= pair[1])
}

fn capacity_ratio_valid(capacity: ExactRatio) -> bool {
    u64::try_from(capacity.numerator())
        .is_ok_and(|numerator| numerator > 0 && numerator <= capacity.denominator())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::CountLimit;
    use serde_json::json;

    #[test]
    fn nonpositive_cpu_capacity_is_rejected() {
        let capacity = match ExactRatio::new(0, 1) {
            Ok(value) => value,
            Err(error) => panic!("zero ratio is canonical: {error}"),
        };
        let quantum = match PositiveU64::new("quantum_instructions", 1) {
            Ok(value) => value,
            Err(error) => panic!("test quantum must be valid: {error}"),
        };
        let effect = NodeEffectSpecification::CpuService {
            vcpus: vec![0],
            capacity,
            quantum_instructions: quantum,
            service_rule: CpuServiceDiscipline::WorkConserving,
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
        let effect = NodeEffectSpecification::RegisterTransform {
            register,
            first_bit: 0,
            bit_count,
            mutation: RegisterMutation::BitFlip { mask: short_mask },
            occurrence: NodeOccurrencePolicy::Every,
        };
        assert!(effect.validate().is_err());
    }

    #[test]
    fn clock_drift_requires_positive_ratio() {
        let effect: NodeEffectSpecification = serde_json::from_value(json!({
            "kind": "clock_transform",
            "parameters": {
                "source": "clock-main",
                "mutation": {"kind": "drift", "parameters": {"ratio": {"numerator": -1, "denominator": 2}}},
                "monotonicity": "allow_backward",
                "overdue_timer_policy": "fire_at_boundary"
            }
        }))
        .unwrap_or_else(|error| panic!("negative reduced ratio must decode: {error}"));
        assert!(effect.validate().is_err());
    }

    #[test]
    fn read_corruption_requires_a_read_access_class() {
        let effect: NodeEffectSpecification = serde_json::from_value(json!({
            "kind": "memory_access_transform",
            "parameters": {
                "range": {"start": 0, "length": 1},
                "accesses": {"fetch": false, "cpu_load": false, "cpu_store": true, "dma_read": false, "dma_write": false, "page_table_walk": false},
                "violate_atomicity": false,
                "mutation": {"kind": "read_corrupt", "parameters": {"mask": "01"}},
                "occurrence": {"kind": "every"}
            }
        }))
        .unwrap_or_else(|error| panic!("closed memory effect must decode: {error}"));
        assert!(effect.validate().is_err());
    }

    #[test]
    fn access_specific_memory_mutations_reject_mixed_classes() {
        let read_corrupt: NodeEffectSpecification = serde_json::from_value(json!({
            "kind": "memory_access_transform",
            "parameters": {
                "range": {"start": 0, "length": 1},
                "accesses": {"fetch": false, "cpu_load": true, "cpu_store": true, "dma_read": false, "dma_write": false, "page_table_walk": false},
                "violate_atomicity": false,
                "mutation": {"kind": "read_corrupt", "parameters": {"mask": "01"}},
                "occurrence": {"kind": "every"}
            }
        }))
        .unwrap_or_else(|error| panic!("closed read mutation must decode: {error}"));
        let lost_write: NodeEffectSpecification = serde_json::from_value(json!({
            "kind": "memory_access_transform",
            "parameters": {
                "range": {"start": 0, "length": 1},
                "accesses": {"fetch": false, "cpu_load": true, "cpu_store": true, "dma_read": false, "dma_write": false, "page_table_walk": false},
                "violate_atomicity": false,
                "mutation": {"kind": "lost_write"},
                "occurrence": {"kind": "every"}
            }
        }))
        .unwrap_or_else(|error| panic!("closed write mutation must decode: {error}"));

        assert!(read_corrupt.validate().is_err());
        assert!(lost_write.validate().is_err());
    }

    #[test]
    fn torn_write_requires_a_nontrivial_selector() {
        for selector in ["00", "ff"] {
            let effect: NodeEffectSpecification = serde_json::from_value(json!({
                "kind": "memory_access_transform",
                "parameters": {
                    "range": {"start": 0, "length": 1},
                    "accesses": {"fetch": false, "cpu_load": false, "cpu_store": true, "dma_read": false, "dma_write": false, "page_table_walk": false},
                    "violate_atomicity": true,
                    "mutation": {"kind": "torn_write", "parameters": {"selector": selector}},
                    "occurrence": {"kind": "every"}
                }
            }))
            .unwrap_or_else(|error| panic!("closed memory effect must decode: {error}"));
            assert!(effect.validate().is_err());
        }
    }
}
