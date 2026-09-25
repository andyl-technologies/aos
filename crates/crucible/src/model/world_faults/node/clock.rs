//! Guest-visible clock-source declarations and canonical constructors.

use super::*;

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
    /// Guest-state-derived calendar epoch in nanoseconds; zero for non-calendar sources.
    pub epoch_ns: i64,
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
    pub(in crate::model) const fn id(&self) -> &SignalId {
        &self.id
    }
}
