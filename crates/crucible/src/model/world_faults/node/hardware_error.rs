//! Guest-visible architecture and platform hardware-error records.

use super::*;

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
