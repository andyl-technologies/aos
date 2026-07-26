//! Errors raised by the live QEMU white-box ABI adapter.

use thiserror::Error;

/// Reports a failure at the live QEMU white-box ABI boundary.
#[derive(Debug, Error)]
pub enum LiveWhiteboxError {
    /// The host did not attest a collision-free x86 port map at setup.
    #[error("live white-box registration requires an x86 port-map setup attestation")]
    SetupAttestationMissing,
    /// A guest requested app-random without a seeded launch configuration.
    #[error("live app-random doorbell request arrived without seeded configuration")]
    AppRandomNotConfigured,
    /// The mapped setup region could not expose this VM's marker queue.
    #[error("mapped live white-box marker queue is unavailable")]
    MappedMarkerQueue {
        /// Underlying mapped-region access error.
        source: crucible_shmem::MappedSetupRegionAccessError,
    },
    /// A required upstream QEMU or GLib symbol was absent.
    #[error("required live white-box capability `{symbol}` is unavailable")]
    CapabilityUnavailable {
        /// Missing process symbol.
        symbol: &'static str,
    },
    /// The QEMU vCPU count exceeded the fixed callback-state bound.
    #[error("live white-box vCPU count {vcpu_count} is outside 1..={maximum}")]
    UnsupportedVcpuCount {
        /// Observed count.
        vcpu_count: u64,
        /// Supported maximum.
        maximum: usize,
    },
    /// The safe registration plan rejected the live configuration.
    #[error("live white-box registration plan failed: {message}")]
    RegistrationPlan {
        /// Stable diagnostic.
        message: String,
    },
    /// Another live white-box state was already published.
    #[error("live white-box callback state is already published")]
    StateAlreadyPublished,
    /// QEMU invoked the callback for an unexpected vCPU.
    #[error("live white-box callback saw vCPU {vcpu_index}, configured count {vcpu_count}")]
    UnexpectedVcpu {
        /// Callback vCPU.
        vcpu_index: usize,
        /// Configured vCPU count.
        vcpu_count: usize,
    },
    /// QEMU did not return a register descriptor array.
    #[error("QEMU register list is unavailable for live white-box vCPU {vcpu_index}")]
    RegisterListUnavailable {
        /// Callback vCPU.
        vcpu_index: usize,
    },
    /// The x86 payload or port register was absent.
    #[error("required rax/rcx/rdx registers are unavailable for live white-box vCPU {vcpu_index}")]
    RequiredRegistersUnavailable {
        /// Callback vCPU.
        vcpu_index: usize,
    },
    /// GLib could not allocate a byte-array adapter.
    #[error("GLib byte-array allocation failed")]
    ByteArrayAllocation,
    /// QEMU rejected a requested register read.
    #[error("QEMU register read failed in live white-box callback")]
    RegisterRead,
    /// A guest-provided payload length did not fit the host address size.
    #[error("guest white-box payload length {len} does not fit host usize")]
    PayloadLengthOverflow {
        /// Guest-provided length.
        len: u64,
    },
    /// The safe doorbell callback rejected the live event.
    #[error("safe white-box callback failed: {message}")]
    Callback {
        /// Stable callback diagnostic.
        message: String,
    },
}
