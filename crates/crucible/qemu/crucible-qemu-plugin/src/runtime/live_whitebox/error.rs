//! Errors raised by the live QEMU white-box ABI adapter.

use thiserror::Error;

/// Reports a failure at the live QEMU white-box ABI boundary.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LiveWhiteboxError {
    /// The host did not provide the architecture's collision-free attestation.
    #[error("live white-box registration requires a matching architecture setup attestation")]
    SetupAttestationMissing,
    /// A guest requested app-random without a seeded launch configuration.
    #[error("live app-random doorbell request arrived without seeded configuration")]
    AppRandomNotConfigured,
    /// A second logical restore attempted to reuse the consumed continuation.
    #[error("live app-random restore continuation was already applied")]
    AppRandomRestoreAlreadyApplied,
    /// A second logical restore attempted to reuse the consumed catalog.
    #[error("live selectable restore continuation was already applied")]
    SelectableRestoreAlreadyApplied,
    /// A selectable message arrived without a negotiated v4 catalog plan.
    #[error("live selectable doorbell message arrived without a catalog plan")]
    SelectableNotConfigured,
    /// The mapped setup region could not expose this VM's marker queue.
    #[error("mapped live white-box marker queue is unavailable")]
    MappedMarkerQueue {
        /// Underlying mapped-region access error.
        source: crucible_qemu_shmem::MappedSetupRegionAccessError,
    },
    /// The mapped setup region could not expose this VM's reply queue.
    #[error("mapped live selectable reply queue is unavailable")]
    MappedSelectableReplyQueue {
        /// Underlying mapped-region access error.
        source: crucible_qemu_shmem::MappedSetupRegionAccessError,
    },
    /// The mapped setup region could not expose this VM's introspection rings.
    #[error("mapped guest-introspection rings are unavailable")]
    MappedGuestIntrospectionRings {
        /// Underlying mapped-region access error.
        source: crucible_qemu_shmem::MappedSetupRegionAccessError,
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
    #[error("live white-box registration plan failed: {source}")]
    RegistrationPlan {
        /// Original doorbell validation failure.
        source: crate::WhiteboxDoorbellError,
    },
    /// The launch-authenticated selectable catalog rejected registration.
    #[error("live white-box registration plan failed: {source}")]
    CatalogRegistration {
        /// Original catalog validation failure.
        source: crate::SelectableCatalogError,
    },
    /// The enabled doorbell plan did not select a trap installation.
    #[error(
        "live white-box registration plan failed: enabled live white-box plan did not install a trap"
    )]
    TrapInstallationMissing,
    /// Branch decisions were supplied without their app-random producer.
    #[error(
        "live white-box registration plan failed: app-random branch plan requires an enabled app-random producer"
    )]
    AppRandomBranchProducerMissing,
    /// Branch decisions named a different app-random producer node.
    #[error(
        "live white-box registration plan failed: app-random branch plan names another producer node"
    )]
    AppRandomBranchNodeMismatch,
    /// The selectable handoff had no installed vCPU callback state.
    #[error(
        "live white-box registration plan failed: live selectable handoff requires installed vCPU callback state"
    )]
    VcpuCallbackStateMissing,
    /// Registration could not resolve a required QEMU observation capability.
    #[error(
        "live white-box registration plan failed: required QEMU capability {symbol} is unavailable"
    )]
    RegistrationCapabilityUnavailable {
        /// Missing process symbol.
        symbol: &'static str,
    },
    /// QEMU refused registration of the live catalog owner.
    #[error(
        "live white-box registration plan failed: {symbol} refused the live catalog owner with status {status}"
    )]
    CatalogOwnerRefused {
        /// Registration entry point.
        symbol: &'static str,
        /// Original QEMU refusal status.
        status: i32,
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
    /// The architecture-specific payload pointer or length register was absent.
    #[error(
        "required payload register pair (rax/rcx or eax/ecx on x86; x0/x1 on aarch64) is unavailable for live white-box vCPU {vcpu_index}"
    )]
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
    /// QEMU could not provide the non-mutating instruction callback coordinate.
    #[error("QEMU could not observe the exact live white-box instruction icount")]
    IcountObservation,
    /// Translation metadata could not be represented in callback userdata.
    #[error(
        "live white-box instruction location tb_insns={tb_insns} index={index} is not representable"
    )]
    InstructionLocationOverflow {
        /// Number of instructions in the translated block.
        tb_insns: usize,
        /// Zero-based instruction index in the translated block.
        index: usize,
    },
    /// A guest-provided payload length did not fit the host address size.
    #[error("guest white-box payload length {len} does not fit host usize")]
    PayloadLengthOverflow {
        /// Guest-provided length.
        len: u64,
    },
    /// A guest-provided payload exceeds the callback read bound.
    #[error("guest white-box payload length {len} exceeds maximum {maximum}")]
    PayloadTooLarge {
        /// Guest-provided length.
        len: usize,
        /// Fixed callback read bound.
        maximum: usize,
    },
    /// The guest-memory adapter could not read the live event.
    #[error("safe white-box callback failed: {source}")]
    GuestMemoryRead {
        /// Original guest-memory failure.
        source: crate::GuestMemoryReadError,
    },
    /// The safe observational marker callback rejected the live event.
    #[error("safe white-box callback failed: {source}")]
    DoorbellCallback {
        /// Original doorbell failure.
        source: crate::WhiteboxDoorbellError,
    },
    /// QEMU rejected an observed ready marker.
    #[error(
        "safe white-box callback failed: QEMU rejected ready-marker observation `{name}` with status {status}"
    )]
    ReadyMarkerRefused {
        /// Original decoded marker name, moved from the consumed event.
        name: String,
        /// Original QEMU refusal status.
        status: i32,
    },
    /// A campaign marker arrived while another VMStop was deferred.
    #[error(
        "safe white-box callback failed: campaign boundary `{name}` collided with another deferred VMStop"
    )]
    CampaignMarkerCollision {
        /// Original decoded marker name, moved from the consumed event.
        name: String,
    },
    /// QEMU rejected the campaign boundary's requested TB exit.
    #[error(
        "safe white-box callback failed: QEMU rejected campaign boundary `{name}` TB exit with status {status}"
    )]
    CampaignMarkerExitRefused {
        /// Original decoded marker name, moved from the consumed event.
        name: String,
        /// Original QEMU refusal status.
        status: i32,
    },
    /// A remaining safe doorbell service rejected the live event.
    #[error("safe white-box callback failed: {message}")]
    Callback {
        /// Stable callback diagnostic.
        message: String,
    },
}
