//! Fault-addressable processor, memory, clock, and accelerator schemas.

use super::*;
/// Closed architecture register groups exported by the live QEMU manifest.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNodeRegisterGroup {
    /// Integer data and address registers.
    GeneralPurpose,
    /// Program counters and other explicit control-flow registers.
    ControlFlow,
    /// Integer condition and status flags.
    Flags,
    /// Segment selectors, bases, limits, and attributes.
    Segment,
    /// Translation and execution control registers.
    Control,
    /// Other guest-visible architecture system registers.
    System,
    /// Guest-visible debug registers.
    Debug,
    /// Floating-point data and control registers.
    FloatingPoint,
    /// SIMD, vector, and predicate registers.
    Vector,
    /// Architecture-defined error status and syndrome registers.
    Error,
}

/// Closed derived-state actions completed by a QEMU register setter.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNodeRegisterSideEffect {
    /// Flushes the vCPU translation lookaside buffer.
    TlbFlush,
    /// Flushes translated-code blocks affected by the new state.
    TranslationBlockFlush,
    /// Recomputes cached flags or architecture execution state.
    FlagsRecompute,
    /// Reevaluates interrupt masking and delivery state.
    InterruptReevaluate,
    /// Rearms timers derived from the mutated register.
    TimerRearm,
    /// Synchronizes the next guest control-flow location.
    ControlFlowSynchronize,
}

/// One architecture register exposed by the live fault ABI.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNodeRegister {
    /// Stable scenario object ID selected by fault bindings.
    pub id: SignalId,
    /// Canonical lowercase name in the QEMU target manifest.
    pub name: String,
    /// Nonzero numeric row ID in the canonical target manifest.
    pub numeric_id: u32,
    /// Closed architecture register group.
    pub group: WorldNodeRegisterGroup,
    /// Register width in bits.
    pub width_bits: u32,
    /// Whether the register has one independent value per vCPU.
    pub per_vcpu: bool,
    /// Ordered model phases at which persistent transforms are safe.
    pub model_phases: Vec<FaultPhase>,
    /// Derived-state actions acknowledged by the architecture setter.
    pub side_effects: Vec<WorldNodeRegisterSideEffect>,
    /// Whether an exact one-shot mutation is supported.
    pub impulse: bool,
    /// Whether an exact persistent transform is supported.
    pub persistent: bool,
    /// Whether the architectural value and persistent transform have VMState coverage.
    pub vmstate: bool,
    /// Lowercase byte-order hex mask of bits which the ABI may mutate.
    pub writable_mask_hex: String,
    /// Lowercase byte-order hex mask of architecturally reserved bits.
    pub reserved_mask_hex: String,
    /// Lowercase byte-order hex mask of writes which are architecturally ignored.
    pub ignored_mask_hex: String,
    /// Lowercase byte-order hex mask of readable but immutable bits.
    pub read_only_mask_hex: String,
}
impl WorldNodeRegister {
    pub(super) const fn id(&self) -> &SignalId {
        &self.id
    }

    /// Returns whether every bit in a nonempty range is manifest-writable.
    #[must_use]
    pub fn range_is_writable(&self, first_bit: u32, bit_count: u32) -> bool {
        let Some(end) = first_bit.checked_add(bit_count) else {
            return false;
        };
        if bit_count == 0 || end > self.width_bits {
            return false;
        }
        let Some(mask) = decode_world_mask(&self.writable_mask_hex) else {
            return false;
        };
        (first_bit..end).all(|bit| {
            let byte = (bit / 8) as usize;
            mask.get(byte)
                .is_some_and(|value| value & (1_u8 << (bit % 8)) != 0)
        })
    }
}

/// One guest memory address space exposed by the live fault ABI.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNodeAddressSpace {
    /// Stable address-space ID.
    pub id: SignalId,
    /// Inclusive first address.
    #[serde(
        deserialize_with = "super::super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::super::toml::serialize_u64_toml_number_or_string"
    )]
    pub start_address: u64,
    /// Positive byte length.
    #[serde(
        deserialize_with = "super::super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::super::toml::serialize_u64_toml_number_or_string"
    )]
    pub length_bytes: u64,
}
impl WorldNodeAddressSpace {
    pub(super) const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// Closed interrupt-controller family exposed by the live fault ABI.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNodeInterruptFamily {
    /// x86 local-APIC fixed interrupt.
    X86LocalApicFixed,
    /// x86 inter-processor interrupt.
    X86Ipi,
    /// x86 I/O-APIC routed interrupt.
    X86IoApic,
    /// x86 legacy 8259 PIC interrupt.
    X86Pic,
    /// x86 PCI MSI interrupt.
    X86Msi,
    /// x86 PCI MSI-X interrupt.
    X86MsiX,
    /// x86 non-maskable interrupt.
    X86Nmi,
    /// x86 architectural local-APIC timer interrupt.
    X86Timer,
    /// Arm GIC software-generated interrupt.
    ArmGicSgi,
    /// Arm GIC private peripheral interrupt.
    ArmGicPpi,
    /// Arm GIC shared peripheral interrupt.
    ArmGicSpi,
    /// Arm GIC locality-specific peripheral interrupt.
    ArmGicLpi,
    /// Arm architectural timer interrupt routed as a PPI.
    ArmTimer,
}

/// Electrical trigger mode for one interrupt manifest row.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNodeInterruptTrigger {
    /// One transition creates one pending event.
    Edge,
    /// An asserted line may re-pend after acknowledgement.
    Level,
}

/// Active electrical polarity for one interrupt source.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNodeInterruptPolarity {
    /// A high level or rising edge is active.
    ActiveHigh,
    /// A low level or falling edge is active.
    ActiveLow,
}

/// Controller-state transition used when delivery is dropped.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNodeInterruptDeliveryDrop {
    /// The selected pending edge is consumed without making it active.
    ConsumeEdge,
    /// The sampled level is consumed and re-pends while the line remains asserted.
    RependAssertedLevel,
}

/// One fully routed interrupt exposed by the live fault ABI.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNodeInterrupt {
    /// Stable manifest row ID.
    pub id: SignalId,
    /// Interrupt controller ID.
    pub controller: SignalId,
    /// Interrupt source ID.
    pub source: SignalId,
    /// Realized QEMU controller implementation and version.
    pub controller_version: String,
    /// Architecture interrupt family.
    pub family: WorldNodeInterruptFamily,
    /// Inclusive first vector or INTID the source may produce at runtime.
    pub vector_start: u32,
    /// Inclusive last vector or INTID the source may produce at runtime.
    pub vector_end: u32,
    /// Inclusive first vector accepted by replacement mutations.
    pub replacement_vector_start: u32,
    /// Inclusive last vector accepted by replacement mutations.
    pub replacement_vector_end: u32,
    /// Electrical trigger mode.
    pub trigger: WorldNodeInterruptTrigger,
    /// Electrical active polarity.
    pub polarity: WorldNodeInterruptPolarity,
    /// Closed set of routable target vCPU indices.
    pub target_vcpus: Vec<u32>,
    /// Ordered unique fault interception phases implemented for this row.
    pub model_phases: Vec<FaultPhase>,
    /// Controller priority value used for deterministic ordering.
    pub priority: u16,
    /// Delivery-drop controller-state transition.
    pub delivery_drop: WorldNodeInterruptDeliveryDrop,
    /// Whether controller and fault overlay state are covered by VMState.
    pub vmstate: bool,
}
impl WorldNodeInterrupt {
    pub(super) const fn id(&self) -> &SignalId {
        &self.id
    }

    const fn architecture_matches(&self, architecture: WorldNodeArchitecture) -> bool {
        matches!(
            (architecture, self.family),
            (
                WorldNodeArchitecture::X86_64,
                WorldNodeInterruptFamily::X86LocalApicFixed
                    | WorldNodeInterruptFamily::X86Ipi
                    | WorldNodeInterruptFamily::X86IoApic
                    | WorldNodeInterruptFamily::X86Pic
                    | WorldNodeInterruptFamily::X86Msi
                    | WorldNodeInterruptFamily::X86MsiX
                    | WorldNodeInterruptFamily::X86Nmi
                    | WorldNodeInterruptFamily::X86Timer
            ) | (
                WorldNodeArchitecture::Aarch64,
                WorldNodeInterruptFamily::ArmGicSgi
                    | WorldNodeInterruptFamily::ArmGicPpi
                    | WorldNodeInterruptFamily::ArmGicSpi
                    | WorldNodeInterruptFamily::ArmGicLpi
                    | WorldNodeInterruptFamily::ArmTimer
            )
        )
    }

    fn architectural_vector_valid(&self, vector: u32) -> bool {
        match self.family {
            WorldNodeInterruptFamily::X86Nmi => vector == 2,
            WorldNodeInterruptFamily::X86Pic => vector <= 255,
            WorldNodeInterruptFamily::X86LocalApicFixed
            | WorldNodeInterruptFamily::X86Ipi
            | WorldNodeInterruptFamily::X86IoApic
            | WorldNodeInterruptFamily::X86Msi
            | WorldNodeInterruptFamily::X86MsiX
            | WorldNodeInterruptFamily::X86Timer => (16..=255).contains(&vector),
            WorldNodeInterruptFamily::ArmGicSgi => vector <= 15,
            WorldNodeInterruptFamily::ArmGicPpi | WorldNodeInterruptFamily::ArmTimer => {
                (16..=31).contains(&vector)
            }
            WorldNodeInterruptFamily::ArmGicSpi => (32..=1_019).contains(&vector),
            WorldNodeInterruptFamily::ArmGicLpi => (8_192..=16_777_215).contains(&vector),
        }
    }

    const fn fixed_edge_family(&self) -> bool {
        matches!(
            self.family,
            WorldNodeInterruptFamily::X86Ipi
                | WorldNodeInterruptFamily::X86Msi
                | WorldNodeInterruptFamily::X86MsiX
                | WorldNodeInterruptFamily::X86Nmi
                | WorldNodeInterruptFamily::ArmGicSgi
                | WorldNodeInterruptFamily::ArmGicLpi
        )
    }
}

/// Closed guest-visible clock source family.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNodeClockSourceKind {
    /// x86 timestamp counter.
    X86Tsc,
    /// x86 MC146818-compatible real-time clock.
    X86Rtc,
    /// x86 i8254 programmable interval timer.
    X86Pit,
    /// x86 high precision event timer.
    X86Hpet,
    /// x86 local APIC timer.
    X86ApicTimer,
    /// x86 ACPI power-management timer.
    X86AcpiPmTimer,
    /// AArch64 architectural generic counter.
    ArmCounter,
    /// AArch64 PL031-compatible real-time clock.
    ArmRtc,
    /// A registered device-specific clock.
    Device,
}

/// Deterministic coordinate underlying a guest-visible clock source.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNodeClockBaseDomain {
    /// Deterministic scheduler virtual time.
    SchedulerVirtual,
    /// A deterministic RTC epoch derived from scheduler virtual time.
    RtcEpoch,
}

/// Relationship between a clock source and guest-programmable timers.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNodeClockTimerRelationship {
    /// The source has no programmable timer deadline.
    None,
    /// Guest timer deadlines are programmed in this source's domain.
    Programmable,
}

/// Required default policy for a clock value that moves backward.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNodeClockMonotonicity {
    /// The source contract permits backward values or architectural wrap.
    AllowBackward,
    /// QEMU clamps backward values to the last observed value.
    ClampMonotonic,
    /// QEMU terminally faults the source on a backward value.
    FaultOnBackward,
}

/// One guest-visible clock source exposed by the live fault ABI.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNodeClockSource {
    /// Stable clock-source ID.
    pub id: SignalId,
    /// QEMU subsystem that implements reads and related timer deadlines.
    pub implementation: String,
    /// Closed architecture or device clock family.
    pub source_kind: WorldNodeClockSourceKind,
    /// Deterministic coordinate underlying the source.
    pub base_domain: WorldNodeClockBaseDomain,
    /// Relationship to a guest-programmable timer.
    pub timer_relationship: WorldNodeClockTimerRelationship,
    /// Architecturally visible source width.
    pub width_bits: u32,
    /// Whether the architectural source wraps at its declared width.
    pub wraps: bool,
    /// Whether the architecture can report a source read error.
    pub read_error: bool,
    /// Exact tick-frequency numerator in ticks per second.
    pub frequency_numerator: u64,
    /// Exact tick-frequency denominator in ticks per second.
    pub frequency_denominator: u64,
    /// Exact clock opportunities implemented by the QEMU source.
    pub model_phases: Vec<FaultPhase>,
    /// Required handling for backward transformed values.
    pub monotonicity: WorldNodeClockMonotonicity,
    /// Whether all source, transform, timer, and synchronization state migrates.
    pub vmstate: bool,
    /// Exact clock transform semantic version.
    pub semantic_version: u16,
}
impl WorldNodeClockSource {
    pub(super) const fn id(&self) -> &SignalId {
        &self.id
    }

    /// Builds the exact QEMU TCG x86 timestamp-counter contract.
    #[must_use]
    pub fn emulated_x86_tsc_v1(id: SignalId) -> Self {
        Self {
            id,
            implementation: "target/i386/tcg".to_owned(),
            source_kind: WorldNodeClockSourceKind::X86Tsc,
            base_domain: WorldNodeClockBaseDomain::SchedulerVirtual,
            timer_relationship: WorldNodeClockTimerRelationship::None,
            width_bits: 64,
            wraps: true,
            read_error: false,
            frequency_numerator: 1_000_000_000,
            frequency_denominator: 1,
            model_phases: vec![
                FaultPhase::ClockRead,
                FaultPhase::Synchronize,
                FaultPhase::SourceSwitch,
            ],
            monotonicity: WorldNodeClockMonotonicity::ClampMonotonic,
            vmstate: true,
            semantic_version: 1,
        }
    }

    /// Builds the exact QEMU MC146818 RTC contract.
    #[must_use]
    pub fn emulated_x86_rtc_v1(id: SignalId) -> Self {
        Self::emulated_programmable_v1(
            id,
            "hw/rtc/mc146818rtc",
            WorldNodeClockSourceKind::X86Rtc,
            WorldNodeClockBaseDomain::RtcEpoch,
            64,
            false,
            1_000_000_000,
            WorldNodeClockMonotonicity::AllowBackward,
        )
    }

    /// Builds the exact QEMU i8254 PIT contract.
    #[must_use]
    pub fn emulated_x86_pit_v1(id: SignalId) -> Self {
        Self::emulated_programmable_v1(
            id,
            "hw/timer/i8254",
            WorldNodeClockSourceKind::X86Pit,
            WorldNodeClockBaseDomain::SchedulerVirtual,
            64,
            false,
            1_000_000_000,
            WorldNodeClockMonotonicity::AllowBackward,
        )
    }

    /// Builds the exact QEMU HPET contract.
    #[must_use]
    pub fn emulated_x86_hpet_v1(id: SignalId) -> Self {
        Self::emulated_programmable_v1(
            id,
            "hw/timer/hpet",
            WorldNodeClockSourceKind::X86Hpet,
            WorldNodeClockBaseDomain::SchedulerVirtual,
            64,
            true,
            10_000_000,
            WorldNodeClockMonotonicity::AllowBackward,
        )
    }

    /// Builds the exact QEMU userspace local-APIC timer contract.
    #[must_use]
    pub fn emulated_x86_apic_timer_v1(id: SignalId) -> Self {
        Self::emulated_programmable_v1(
            id,
            "hw/intc/apic",
            WorldNodeClockSourceKind::X86ApicTimer,
            WorldNodeClockBaseDomain::SchedulerVirtual,
            64,
            false,
            1_000_000_000,
            WorldNodeClockMonotonicity::AllowBackward,
        )
    }

    /// Builds the exact QEMU ACPI power-management timer contract.
    #[must_use]
    pub fn emulated_x86_acpi_pm_timer_v1(id: SignalId) -> Self {
        Self::emulated_programmable_v1(
            id,
            "hw/acpi/core",
            WorldNodeClockSourceKind::X86AcpiPmTimer,
            WorldNodeClockBaseDomain::SchedulerVirtual,
            24,
            true,
            3_579_545,
            WorldNodeClockMonotonicity::AllowBackward,
        )
    }

    /// Builds the exact QEMU AArch64 architectural-counter contract.
    #[must_use]
    pub fn emulated_arm_counter_v1(id: SignalId, frequency_hz: u64) -> Self {
        Self::emulated_programmable_v1(
            id,
            "target/arm/generic-timer",
            WorldNodeClockSourceKind::ArmCounter,
            WorldNodeClockBaseDomain::SchedulerVirtual,
            64,
            false,
            frequency_hz,
            WorldNodeClockMonotonicity::ClampMonotonic,
        )
    }

    /// Builds the exact QEMU PL031 RTC contract.
    #[must_use]
    pub fn emulated_arm_rtc_v1(id: SignalId) -> Self {
        Self::emulated_programmable_v1(
            id,
            "hw/rtc/pl031",
            WorldNodeClockSourceKind::ArmRtc,
            WorldNodeClockBaseDomain::RtcEpoch,
            32,
            true,
            1,
            WorldNodeClockMonotonicity::AllowBackward,
        )
    }

    // crucible-lint: allow rust-allow -- the clock manifest carries each independent hardware identity and behavior field.
    #[allow(
        clippy::too_many_arguments,
        reason = "the closed clock-source manifest carries independent hardware identity and behavior fields"
    )]
    fn emulated_programmable_v1(
        id: SignalId,
        implementation: &str,
        source_kind: WorldNodeClockSourceKind,
        base_domain: WorldNodeClockBaseDomain,
        width_bits: u32,
        wraps: bool,
        frequency_numerator: u64,
        monotonicity: WorldNodeClockMonotonicity,
    ) -> Self {
        Self {
            id,
            implementation: implementation.to_owned(),
            source_kind,
            base_domain,
            timer_relationship: WorldNodeClockTimerRelationship::Programmable,
            width_bits,
            wraps,
            read_error: false,
            frequency_numerator,
            frequency_denominator: 1,
            model_phases: vec![
                FaultPhase::ClockRead,
                FaultPhase::Arm,
                FaultPhase::Fire,
                FaultPhase::Synchronize,
                FaultPhase::SourceSwitch,
            ],
            monotonicity,
            vmstate: true,
            semantic_version: 1,
        }
    }
}

/// Closed accelerator class implemented by the patched QEMU device.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNodeAcceleratorKind {
    /// Virtio GPU device.
    Gpu,
    /// Crucible TPU co-simulation device.
    Tpu,
    /// Crucible FPGA co-simulation device.
    Fpga,
}

/// One accelerator device exposed by the live fault ABI.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNodeAccelerator {
    /// Stable device ID.
    pub id: SignalId,
    /// Canonically ordered accelerator classes exposed by this device.
    pub classes: Vec<WorldNodeAcceleratorKind>,
    /// Exact accelerator fault-device semantic version.
    pub semantic_version: u16,
    /// Content address of the device-specific capability manifest.
    pub capability_manifest: ContentHash,
}
impl WorldNodeAccelerator {
    pub(super) const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// Closed architecture ABIs supported by live QEMU node faults.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNodeArchitecture {
    /// x86-64 architectural register, interrupt, and machine-check ABI.
    X86_64,
    /// AArch64 architectural register, interrupt, and hardware-error ABI.
    Aarch64,
}

/// Closed guest-visible hardware-error record families.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNodeHardwareErrorRecordKind {
    /// x86 machine-check architecture record.
    X86MachineCheck,
    /// AArch64 RAS synchronous abort or asynchronous SError record.
    Aarch64Ras,
    /// Platform or architecture memory-ECC record.
    MemoryEcc,
}

/// Closed hardware-error severity and delivery classes.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNodeHardwareErrorClass {
    /// Corrected error reported without an uncorrectable exception.
    Corrected,
    /// Uncorrectable error from which execution may recover.
    Recoverable,
    /// Fatal error whose architecture path terminates or resets the node.
    Fatal,
    /// AArch64 synchronous external abort.
    Synchronous,
    /// AArch64 asynchronous SError.
    Asynchronous,
}

/// Closed hardware-error publication and delivery mechanisms.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNodeHardwareErrorMechanism {
    /// x86 machine-check architecture banks and vector 18.
    X86Mca,
    /// ACPI APEI GHES platform memory-error record.
    AcpiGhes,
    /// AArch64 RAS synchronous abort or SError delivery.
    Aarch64Ras,
}

/// One guest-observable consequence permitted by a hardware-error row.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNodeHardwareErrorVisibility {
    /// Publishes an architecture or firmware telemetry record.
    Telemetry,
    /// Raises the corrected-error interrupt supported by the realized platform.
    Interrupt,
    /// Delivers the complete architecture exception described by the request.
    Exception,
}

/// One exact hardware-error row exposed by the realized QEMU machine.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNodeHardwareError {
    /// Stable row identity selected by a hardware-error fault.
    pub id: SignalId,
    /// Stable architecture bank or platform-record identity.
    pub bank: SignalId,
    /// Stable memory-channel identity.
    pub channel: SignalId,
    /// Stable memory-rank identity.
    pub rank: SignalId,
    /// Exact firmware or table prerequisite.
    pub firmware: SignalId,
    /// Exact resulting QEMU and guest-visible state contract.
    pub state: SignalId,
    /// Typed architecture or platform record family.
    pub record_kind: WorldNodeHardwareErrorRecordKind,
    /// Error severity or AArch64 delivery class.
    pub error_class: WorldNodeHardwareErrorClass,
    /// Architecture or platform publication mechanism.
    pub mechanism: WorldNodeHardwareErrorMechanism,
    /// Canonically ordered guest-visible consequences admitted by this row.
    pub visibility: Vec<WorldNodeHardwareErrorVisibility>,
    /// First numeric architecture bank or platform record.
    pub bank_number: u32,
    /// Number of consecutive banks or records in this row.
    pub bank_count: u32,
    /// Required architecture vector or exception class.
    pub vector: u32,
    /// Status bits that every request must set.
    #[serde(
        deserialize_with = "super::super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::super::toml::serialize_u64_toml_number_or_string"
    )]
    pub status_required: u64,
    /// Complete mask of status bits a request may set.
    #[serde(
        deserialize_with = "super::super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::super::toml::serialize_u64_toml_number_or_string"
    )]
    pub status_allowed: u64,
    /// Syndrome bits that every request must set.
    #[serde(
        deserialize_with = "super::super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::super::toml::serialize_u64_toml_number_or_string"
    )]
    pub syndrome_required: u64,
    /// Complete mask of syndrome bits a request may set.
    #[serde(
        deserialize_with = "super::super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::super::toml::serialize_u64_toml_number_or_string"
    )]
    pub syndrome_allowed: u64,
    /// Ordered model phases at which this row may apply.
    pub model_phases: Vec<FaultPhase>,
    /// Canonically ordered x86 CPLs or AArch64 exception levels (0 through 3).
    pub privilege_levels: Vec<u8>,
    /// Identifies a corrected rather than uncorrectable record.
    pub corrected: bool,
    /// Allows architecture masking to defer delivery.
    pub maskable: bool,
    /// Confirms that all resulting architecture and platform state has VMState coverage.
    pub vmstate: bool,
}

impl WorldNodeArchitecture {
    /// Returns the canonical selector spelling used by resolved register targets.
    #[must_use]
    pub const fn selector_id(self) -> &'static str {
        match self {
            Self::X86_64 => "x86-64",
            Self::Aarch64 => "aarch64",
        }
    }

    pub(super) const fn matches_vm(self, architecture: VmArchitecture) -> bool {
        matches!(
            (self, architecture),
            (Self::X86_64, VmArchitecture::X86_64) | (Self::Aarch64, VmArchitecture::Aarch64)
        )
    }
}

/// One closed VM-node fault capability declaration.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNodeFaultCapabilities {
    /// Stable capability declaration ID.
    pub id: SignalId,
    /// Referenced VM-node ID.
    pub node: SignalId,
    /// Registered architecture ABI.
    pub architecture: WorldNodeArchitecture,
    /// Exact realized QOM CPU typename reported by QEMU.
    pub cpu_model: String,
    /// Content address of the exact register schema.
    pub register_schema: ContentHash,
    /// Exact architecture register manifest.
    pub registers: Vec<WorldNodeRegister>,
    /// Registered memory address spaces.
    pub address_spaces: Vec<WorldNodeAddressSpace>,
    /// Guest page size used by memory mutation contracts.
    #[serde(
        deserialize_with = "super::super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::super::toml::serialize_u64_toml_number_or_string"
    )]
    pub page_bytes: u64,
    /// Exact GPA-to-DRAM coordinate mapping implemented by patched QEMU.
    pub dram_geometry: WorldNodeDramGeometry,
    /// Exact routable interrupt manifest.
    pub interrupts: Vec<WorldNodeInterrupt>,
    /// Exact architecture and platform hardware-error manifest.
    pub hardware_errors: Vec<WorldNodeHardwareError>,
    /// Registered guest-visible clock sources.
    pub clock_sources: Vec<WorldNodeClockSource>,
    /// Registered accelerator devices.
    pub accelerators: Vec<WorldNodeAccelerator>,
    /// Exact guest event markers eligible to satisfy node-ready policies.
    pub ready_markers: Vec<SignalId>,
    /// Exact capability schema semantic version.
    pub semantic_version: u16,
}
impl WorldNodeFaultCapabilities {
    pub(super) const fn id(&self) -> &SignalId {
        &self.id
    }
    pub(super) fn validate(&self) -> Result<(), WorldFaultTopologyError> {
        require(
            self.semantic_version == 1,
            "node capability semantic version",
        )?;
        require(self.page_bytes.is_power_of_two(), "node page geometry")?;
        self.dram_geometry.validate()?;
        require(!self.registers.is_empty(), "node register manifest")?;
        require(!self.address_spaces.is_empty(), "node address spaces")?;
        let mut numeric_ids = BTreeSet::new();
        let mut register_names = BTreeSet::new();
        for register in &self.registers {
            let mask_hex_bytes = usize::try_from(register.width_bits)
                .ok()
                .map(|width| width.div_ceil(8).saturating_mul(2));
            require(
                register.numeric_id > 0
                    && register.width_bits > 0
                    && register.width_bits <= 65_536
                    && register.per_vcpu,
                "node register capability",
            )?;
            require(
                numeric_ids.insert(register.numeric_id)
                    && register_names.insert(register.name.as_str()),
                "node register manifest identity",
            )?;
            require(
                !register.name.is_empty()
                    && register.name.len() <= 96
                    && register.name.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'-' | b'_' | b'.')
                    }),
                "node register name",
            )?;
            require(
                register.model_phases.iter().all(|phase| {
                    matches!(
                        phase,
                        FaultPhase::BeforeInstruction | FaultPhase::AfterInstruction
                    )
                }) && !register
                    .model_phases
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1]),
                "node register model phases",
            )?;
            require(
                !register
                    .side_effects
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1]),
                "node register side effects",
            )?;
            let masks = [
                &register.writable_mask_hex,
                &register.reserved_mask_hex,
                &register.ignored_mask_hex,
                &register.read_only_mask_hex,
            ];
            require(
                mask_hex_bytes.is_some_and(|length| {
                    masks.iter().all(|mask| {
                        mask.len() == length
                            && mask
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    })
                }),
                "node register masks",
            )?;
            let decoded_masks = masks
                .map(|mask| decode_world_mask(mask))
                .into_iter()
                .collect::<Option<Vec<_>>>();
            require(
                decoded_masks.is_some_and(|masks| {
                    let writable = masks[0].iter().any(|byte| *byte != 0);
                    (0..register.width_bits).all(|bit| {
                        let byte = (bit / 8) as usize;
                        let mask = 1_u8 << (bit % 8);
                        masks.iter().filter(|value| value[byte] & mask != 0).count() == 1
                    }) && (register.width_bits..register.width_bits.div_ceil(8) * 8).all(|bit| {
                        let byte = (bit / 8) as usize;
                        let mask = 1_u8 << (bit % 8);
                        masks.iter().all(|value| value[byte] & mask == 0)
                    }) && if writable {
                        (register.impulse || register.persistent)
                            && register.vmstate
                            && !register.model_phases.is_empty()
                    } else {
                        !register.impulse
                            && !register.persistent
                            && register.model_phases.is_empty()
                            && register.side_effects.is_empty()
                    }
                }),
                "node register mask partition",
            )?;
        }
        require(
            !self.cpu_model.is_empty()
                && self.cpu_model.len() <= 96
                && self
                    .cpu_model
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_whitespace()),
            "node realized CPU model",
        )?;
        for space in &self.address_spaces {
            require(space.length_bytes > 0, "node address-space length")?;
            require(
                space
                    .start_address
                    .checked_add(space.length_bytes)
                    .is_some(),
                "node address-space range",
            )?;
        }
        for interrupt in &self.interrupts {
            require(
                interrupt.architecture_matches(self.architecture),
                "node interrupt architecture family",
            )?;
            require(
                !interrupt.controller_version.is_empty()
                    && interrupt.controller_version.len() <= 96
                    && interrupt
                        .controller_version
                        .bytes()
                        .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_whitespace()),
                "node interrupt controller version",
            )?;
            require(
                interrupt.architectural_vector_valid(interrupt.vector_start)
                    && interrupt.architectural_vector_valid(interrupt.vector_end)
                    && interrupt.architectural_vector_valid(interrupt.replacement_vector_start)
                    && interrupt.architectural_vector_valid(interrupt.replacement_vector_end)
                    && interrupt.vector_start <= interrupt.vector_end
                    && interrupt.replacement_vector_start <= interrupt.replacement_vector_end,
                "node interrupt vector range",
            )?;
            require(
                !interrupt.target_vcpus.is_empty()
                    && !interrupt
                        .target_vcpus
                        .windows(2)
                        .any(|pair| pair[0] >= pair[1]),
                "node interrupt targets",
            )?;
            require(
                !interrupt.model_phases.is_empty()
                    && interrupt.model_phases.iter().all(|phase| {
                        matches!(
                            phase,
                            FaultPhase::Raise | FaultPhase::Route | FaultPhase::InterruptDeliver
                        )
                    })
                    && !interrupt
                        .model_phases
                        .windows(2)
                        .any(|pair| pair[0] >= pair[1]),
                "node interrupt model phases",
            )?;
            require(interrupt.priority <= 255, "node interrupt priority")?;
            require(interrupt.vmstate, "node interrupt VMState coverage")?;
            require(
                !interrupt.fixed_edge_family()
                    || interrupt.trigger == WorldNodeInterruptTrigger::Edge,
                "node interrupt architecture trigger",
            )?;
            require(
                matches!(
                    (interrupt.trigger, interrupt.delivery_drop),
                    (
                        WorldNodeInterruptTrigger::Edge,
                        WorldNodeInterruptDeliveryDrop::ConsumeEdge
                    ) | (
                        WorldNodeInterruptTrigger::Level,
                        WorldNodeInterruptDeliveryDrop::RependAssertedLevel
                    )
                ),
                "node interrupt delivery-drop state",
            )?;
        }
        require(
            !self
                .hardware_errors
                .windows(2)
                .any(|pair| pair[0].id >= pair[1].id),
            "node hardware-error manifest order",
        )?;
        for error in &self.hardware_errors {
            let architecture_matches = matches!(
                (self.architecture, error.record_kind, error.mechanism),
                (
                    WorldNodeArchitecture::X86_64,
                    WorldNodeHardwareErrorRecordKind::X86MachineCheck,
                    WorldNodeHardwareErrorMechanism::X86Mca
                ) | (
                    WorldNodeArchitecture::X86_64,
                    WorldNodeHardwareErrorRecordKind::MemoryEcc,
                    WorldNodeHardwareErrorMechanism::X86Mca
                ) | (
                    WorldNodeArchitecture::Aarch64,
                    WorldNodeHardwareErrorRecordKind::Aarch64Ras,
                    WorldNodeHardwareErrorMechanism::Aarch64Ras
                ) | (
                    WorldNodeArchitecture::Aarch64,
                    WorldNodeHardwareErrorRecordKind::MemoryEcc,
                    WorldNodeHardwareErrorMechanism::AcpiGhes
                )
            );
            require(architecture_matches, "node hardware-error architecture")?;
            require(
                error.bank_count > 0
                    && error.bank_number.checked_add(error.bank_count).is_some()
                    && error.status_required & !error.status_allowed == 0
                    && error.syndrome_required & !error.syndrome_allowed == 0,
                "node hardware-error numeric contract",
            )?;
            require(
                !error.visibility.is_empty()
                    && !error.visibility.windows(2).any(|pair| pair[0] >= pair[1]),
                "node hardware-error visibility",
            )?;
            require(
                !error.model_phases.is_empty()
                    && !error.model_phases.windows(2).any(|pair| pair[0] >= pair[1])
                    && error
                        .model_phases
                        .iter()
                        .all(|phase| match error.record_kind {
                            WorldNodeHardwareErrorRecordKind::X86MachineCheck
                            | WorldNodeHardwareErrorRecordKind::Aarch64Ras => matches!(
                                phase,
                                FaultPhase::BeforeInstruction | FaultPhase::AfterInstruction
                            ),
                            WorldNodeHardwareErrorRecordKind::MemoryEcc => matches!(
                                phase,
                                FaultPhase::Fetch
                                    | FaultPhase::Load
                                    | FaultPhase::Store
                                    | FaultPhase::DmaRead
                                    | FaultPhase::DmaWrite
                                    | FaultPhase::PageTableWalk
                                    | FaultPhase::Refresh
                            ),
                        }),
                "node hardware-error model phases",
            )?;
            require(
                !error.privilege_levels.is_empty()
                    && error.privilege_levels.iter().all(|level| *level <= 3)
                    && !error
                        .privilege_levels
                        .windows(2)
                        .any(|pair| pair[0] >= pair[1]),
                "node hardware-error privilege levels",
            )?;
            let corrected_visibility = error.visibility.iter().any(|visibility| {
                matches!(
                    visibility,
                    WorldNodeHardwareErrorVisibility::Telemetry
                        | WorldNodeHardwareErrorVisibility::Interrupt
                )
            }) && !error
                .visibility
                .contains(&WorldNodeHardwareErrorVisibility::Exception);
            let uncorrectable_visibility =
                error.visibility == [WorldNodeHardwareErrorVisibility::Exception];
            require(
                error.corrected == (error.error_class == WorldNodeHardwareErrorClass::Corrected)
                    && if error.corrected {
                        corrected_visibility
                    } else {
                        uncorrectable_visibility
                    }
                    && error.vmstate,
                "node hardware-error delivery contract",
            )?;
        }
        hard_count(&self.hardware_errors, "node hardware-error manifest", 4_096)?;
        require(!self.clock_sources.is_empty(), "node clock manifest")?;
        for source in &self.clock_sources {
            let architecture_matches = match self.architecture {
                WorldNodeArchitecture::X86_64 => matches!(
                    source.source_kind,
                    WorldNodeClockSourceKind::X86Tsc
                        | WorldNodeClockSourceKind::X86Rtc
                        | WorldNodeClockSourceKind::X86Pit
                        | WorldNodeClockSourceKind::X86Hpet
                        | WorldNodeClockSourceKind::X86ApicTimer
                        | WorldNodeClockSourceKind::X86AcpiPmTimer
                        | WorldNodeClockSourceKind::Device
                ),
                WorldNodeArchitecture::Aarch64 => matches!(
                    source.source_kind,
                    WorldNodeClockSourceKind::ArmCounter
                        | WorldNodeClockSourceKind::ArmRtc
                        | WorldNodeClockSourceKind::Device
                ),
            };
            require(architecture_matches, "node clock architecture")?;
            require(
                !source.implementation.is_empty()
                    && source.implementation.len() <= 96
                    && source
                        .implementation
                        .bytes()
                        .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_whitespace()),
                "node clock implementation",
            )?;
            require(
                source.width_bits > 0
                    && source.width_bits <= 64
                    && source.frequency_numerator > 0
                    && source.frequency_denominator > 0
                    && source.semantic_version == 1
                    && source.vmstate,
                "node clock numeric contract",
            )?;
            require(
                !source.model_phases.is_empty()
                    && source.model_phases.contains(&FaultPhase::ClockRead)
                    && source.model_phases.iter().all(|phase| {
                        matches!(
                            phase,
                            FaultPhase::ClockRead
                                | FaultPhase::Arm
                                | FaultPhase::Fire
                                | FaultPhase::Synchronize
                                | FaultPhase::SourceSwitch
                        )
                    })
                    && !source
                        .model_phases
                        .windows(2)
                        .any(|pair| pair[0] >= pair[1]),
                "node clock model phases",
            )?;
            let programmable =
                source.timer_relationship == WorldNodeClockTimerRelationship::Programmable;
            require(
                programmable
                    == (source.model_phases.contains(&FaultPhase::Arm)
                        && source.model_phases.contains(&FaultPhase::Fire)),
                "node clock timer relationship",
            )?;
        }
        hard_count(&self.clock_sources, "node clock sources", 4_096)?;
        require(
            self.accelerators.iter().all(|device| {
                device.semantic_version == 1
                    && !device.classes.is_empty()
                    && !device.classes.windows(2).any(|pair| pair[0] >= pair[1])
            }),
            "node accelerator semantic version",
        )?;
        require(
            !self.ready_markers.windows(2).any(|pair| pair[0] >= pair[1]),
            "node ready-marker manifest",
        )?;
        hard_count(&self.ready_markers, "node ready markers", 65_536)?;
        hard_count(&self.accelerators, "node accelerators", 1_024)
    }
}

fn decode_world_mask(value: &str) -> Option<Vec<u8>> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = world_hex_nibble(pair[0])?;
            let low = world_hex_nibble(pair[1])?;
            Some((high << 4) | low)
        })
        .collect()
}

const fn world_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

/// Exact striped DRAM geometry used by memory-region fault processes.
///
/// A physical address is split into `interleave_bytes` lines. Successive lines
/// select channel, then bank, then rank; the remaining byte coordinate selects
/// the row using the row size declared by the rowhammer effect. This is the
/// `2c2r16b64` mapping implemented by the current patched-QEMU capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNodeDramGeometry {
    /// Number of interleaved memory channels.
    pub channels: u16,
    /// Number of ranks per channel.
    pub ranks: u16,
    /// Number of banks per rank.
    pub banks: u16,
    /// Number of consecutive bytes assigned before selecting the next channel.
    pub interleave_bytes: u16,
    /// Exact geometry schema semantic version.
    pub semantic_version: u16,
}

impl WorldNodeDramGeometry {
    /// Returns the only DRAM mapping implemented by the current QEMU patch set.
    #[must_use]
    pub const fn emulated_v1() -> Self {
        Self {
            channels: 2,
            ranks: 2,
            banks: 16,
            interleave_bytes: 64,
            semantic_version: 1,
        }
    }

    pub(super) fn validate(self) -> Result<(), WorldFaultTopologyError> {
        require(
            self == Self::emulated_v1(),
            "node DRAM geometry must match qemu 2c2r16b64",
        )
    }
}
