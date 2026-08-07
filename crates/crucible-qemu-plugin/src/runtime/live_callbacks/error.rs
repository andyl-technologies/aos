//! Error taxonomy for live callback registration and dispatch.

use super::*;
use thiserror::Error;

/// An error in live production callback setup or dispatch.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LiveVcpuTimeCallbackError {
    /// A required QEMU callback registration symbol is absent.
    #[error("required live callback capability `{symbol}` is unavailable")]
    CapabilityUnavailable {
        /// Missing QEMU symbol.
        symbol: &'static str,
    },
    /// The live fault-command bridge failed setup or dispatch.
    #[error("live QEMU fault command bridge failed: {source}")]
    FaultCommands {
        /// Typed bridge failure.
        source: crate::FaultCommandBridgeError,
    },
    /// Required live fault-command callback state was not installed.
    #[error("live QEMU fault command callback state is unavailable")]
    FaultCommandStateUnavailable,
    /// The live preemption command or QEMU injection was rejected.
    #[error("live preemption injection failed: {source}")]
    Preemption {
        /// Underlying command validation or QEMU capability error.
        source: PreemptionError,
    },
    /// The shared-memory preemption mailbox could not be consumed.
    #[error("live preemption mailbox failed: {source}")]
    PreemptionMailbox {
        /// Underlying mailbox publication or acknowledgement error.
        source: PreemptionMailboxError,
    },
    /// A logical preemption icount precedes the restored raw-icount origin.
    #[error(
        "preemption {field} icount {logical_icount} precedes logical raw origin {logical_icount_offset}"
    )]
    PreemptionIcountBeforeRawOrigin {
        /// Command field whose logical icount could not be translated.
        field: &'static str,
        /// Scheduler-authored logical icount.
        logical_icount: u64,
        /// Logical offset added to QEMU's raw retired count.
        logical_icount_offset: u64,
    },
    /// The live white-box adapter failed preflight, registration, or dispatch.
    #[error("live white-box callback failed: {message}")]
    WhiteboxCallback {
        /// Stable boundary diagnostic.
        message: String,
    },
    /// Exact virtual-deadline introspection was unavailable during preflight.
    #[error("required exact-deadline capability failed: {source}")]
    ExactDeadlineCapability {
        /// Underlying exact-deadline capability error.
        source: ExactDeadlineError,
    },
    /// Reading QEMU's exact virtual deadline failed at an idle boundary.
    #[error("reading the exact idle deadline failed: {source}")]
    ExactDeadlineRead {
        /// Underlying exact-deadline read error.
        source: ExactDeadlineError,
    },
    /// Enqueueing the scheduler-authorized QEMU idle jump failed.
    #[error("queued idle advance failed: {source}")]
    QueuedIdleAdvance {
        /// Underlying queued-advance error.
        source: QueuedIdleAdvanceError,
    },
    /// The shared idle planning or scheduler wait failed.
    #[error("live idle hot-loop failed: {source}")]
    IdleHotLoop {
        /// Underlying deterministic idle-loop error.
        source: IdleHotLoopError,
    },
    /// The mapped region could not provide the configured VM slot.
    #[error("mapped setup region cannot provide the live callback node slot")]
    MappedNodeSlot {
        /// Underlying typed mapping error.
        source: MappedSetupRegionAccessError,
    },
    /// The mapped region could not provide this VM's fingerprint sample slot.
    #[error("mapped setup region cannot provide the live callback fingerprint slot")]
    MappedFingerprintSlot {
        /// Underlying typed mapping error.
        source: MappedSetupRegionAccessError,
    },
    /// `fingerprint=on` was requested but the loaded QEMU lacks the exports.
    #[error("fingerprint sampling requested but QEMU is missing the fingerprint helper exports")]
    FingerprintCapabilityUnavailable,
    /// Capturing a boundary fingerprint sample failed.
    #[error("boundary fingerprint sampling failed: {source}")]
    FingerprintSample {
        /// Underlying plugin fingerprint sampler error.
        source: FingerprintSamplerError,
    },
    /// The dedicated fingerprint digest worker could not be created.
    #[error("fingerprint digest worker could not start: {message}")]
    FingerprintWorkerSpawn {
        /// Host thread-spawn diagnostic.
        message: String,
    },
    /// The bounded fingerprint digest queue still contains the prior boundary.
    #[error("fingerprint digest worker queue is full at a new sample boundary")]
    FingerprintWorkerQueueFull,
    /// The fingerprint digest worker is no longer accepting captures.
    #[error("fingerprint digest worker is unavailable")]
    FingerprintWorkerUnavailable,
    /// The fingerprint digest worker failed while publishing a prior sample.
    #[error("fingerprint digest worker failed: {message}")]
    FingerprintWorkerFailed {
        /// Stable publication failure diagnostic.
        message: String,
    },
    /// Terminal raw-state export setup or boundary activation failed.
    #[error("terminal raw-state dump failed: {message}")]
    RawStateDump {
        /// Stable underlying raw-state export diagnostic.
        message: String,
    },
    /// A mapped callback ring unexpectedly had no backing entries.
    #[error("mapped callback ring {ring_index} has no backing entries")]
    MappedDirectedRingEmpty {
        /// Directed ring index without storage.
        ring_index: u32,
    },
    /// The selected inbound ring was not the router-to-VM network ring.
    #[error(
        "inbound network ring mismatch: expected {expected_src_slot}->{expected_dst_slot}, got {actual_src_slot}->{actual_dst_slot} at ring {actual_ring_index}"
    )]
    WrongInboundNetworkRing {
        /// Required network-router source slot.
        expected_src_slot: u32,
        /// Required VM destination slot.
        expected_dst_slot: u32,
        /// Selected ring's source slot.
        actual_src_slot: u32,
        /// Selected ring's destination slot.
        actual_dst_slot: u32,
        /// Selected ring index.
        actual_ring_index: u32,
    },
    /// A live network TX enqueue or batch preflight failed.
    #[error("live network TX failed: {source}")]
    NetworkTx {
        /// Underlying fixed-ring TX error.
        source: NetworkTxError,
    },
    /// The inbound network ring could not be previewed or committed.
    #[error("live inbound network frame operation failed: {source}")]
    InboundFrames {
        /// Underlying inbound-ring error.
        source: InboundFrameError,
    },
    /// QEMU's lossless RX queue rejected the validated batch.
    #[error("live network RX injection failed: {source}")]
    NetworkRx {
        /// Underlying lossless RX error.
        source: NetworkRxError,
    },
    /// A live block or 9p adapter failed registration or dispatch.
    #[error("live device callback failed: {source}")]
    LiveDevice {
        /// Underlying block/9p adapter error.
        source: Box<LiveDeviceCallbackError>,
    },
    /// The consumed inbound batch changed after its pre-commit preview.
    #[error("live inbound network commit disagreed with its validated preview")]
    InboundCommitMismatch,
    /// QEMU invoked network TX without registration-fixed network state.
    #[error("live network TX callback state is unavailable")]
    NetworkStateUnavailable,
    /// QEMU re-entered the network TX callback before its prior call returned.
    #[error("live network TX callback was re-entered")]
    NetworkTxReentered,
    /// A pending timer-boundary TX batch exceeded addressable memory.
    #[error("buffered live network TX frame count overflowed")]
    BufferedNetworkTxCountOverflow,
    /// QEMU supplied a null pointer for a nonempty TX payload.
    #[error("live network TX payload is null for nonzero length {payload_len}")]
    NullNetworkTxPayload {
        /// Claimed payload length.
        payload_len: usize,
    },
    /// The mapped icount shift cannot fit the plugin clock representation.
    #[error("mapped setup icount shift {icount_shift} does not fit u8")]
    IcountShiftOutOfRange {
        /// Rejected shared-memory shift.
        icount_shift: u32,
    },
    /// QEMU's raw retired count cannot be reconciled with restored logical time.
    #[error("initial raw icount {raw_icount} exceeds restored logical icount {logical_icount}")]
    InitialRawIcountBeyondLogical {
        /// Raw retired-instruction count read from QEMU during registration.
        raw_icount: u64,
        /// Logical scheduler count restored in the shared-memory slot.
        logical_icount: u64,
    },
    /// Another live callback state pointer is already globally visible.
    #[error("live production callback state is already published")]
    CallbackStateAlreadyPublished,
    /// QEMU invoked the global vCPU-init adapter before state publication.
    #[error("live production callback state is unavailable")]
    CallbackStateUnavailable,
    /// The callback observed a shutdown action without a matching acquire proof.
    #[error("shared shutdown action could not be proven from the region header")]
    SharedShutdownProofUnavailable,
    /// The sole teardown worker disconnected after shared shutdown was observed.
    #[error("shared shutdown could not reach the production teardown worker")]
    TeardownWorkerUnavailable,
    /// QEMU rejected installation of the normal-main-loop completion callback.
    #[error("QEMU rejected time-advance completion registration with status {status}")]
    TimeAdvanceCompletionRegistrationRejected {
        /// Negative errno-style status returned by QEMU.
        status: std::os::raw::c_int,
    },
    /// The normal-main-loop completion callback ran without an outstanding request.
    #[error("time-advance completion arrived without an outstanding idle advance")]
    IdleAdvanceCompletionWithoutPending,
    /// Another idle advance was armed before the current one completed.
    #[error("an idle time advance is already pending")]
    IdleAdvanceAlreadyPending,
    /// QEMU reported an invalid per-vCPU halt or resume transition.
    #[error("live per-vCPU halt tracking failed: {source}")]
    VcpuHaltTracking {
        /// Underlying deterministic halt-tracker error.
        source: RoundRobinError,
    },
    /// QEMU reported vCPU resume before the queued idle jump completed.
    #[error("vCPU resumed while an idle time advance was still pending")]
    ResumeWhileIdleAdvancePending,
    /// The idle-advance completion callback was entered recursively.
    #[error("live idle-advance completion callback was re-entered")]
    IdleAdvanceCompletionReentered,
    /// The pending idle-advance slot was borrowed by another callback.
    #[error("live pending idle-advance state was already borrowed")]
    PendingIdleAdvanceBorrowed,
    /// The per-vCPU halt tracker was borrowed by another callback.
    #[error("live per-vCPU halt state was already borrowed")]
    HaltStateBorrowed,
    /// The fault-command bridge was borrowed without an owned nested pump.
    #[error("live fault-command bridge was already borrowed")]
    FaultCommandStateBorrowed,
    /// A prior panic poisoned the pending idle-advance slot.
    #[error("live time callback pending state is poisoned")]
    CallbackStatePoisoned,
    /// A prior panic poisoned the per-vCPU halt tracker.
    #[error("live per-vCPU halt state is poisoned")]
    HaltStatePoisoned,
    /// Raw guest instruction progress changed while a queued idle jump was pending.
    #[error(
        "raw icount changed during idle advance: expected {expected_raw_icount}, observed {observed_raw_icount}"
    )]
    IdleAdvanceRawIcountChanged {
        /// Raw instruction count captured with the queued request.
        expected_raw_icount: u64,
        /// Raw instruction count observed at validation or completion.
        observed_raw_icount: u64,
    },
    /// Guest instructions retired while QEMU had an idle time jump outstanding.
    #[error(
        "raw icount advanced during a pending idle jump: expected {expected_raw_icount}, observed {observed_raw_icount}"
    )]
    GuestProgressWhileIdleAdvancePending {
        /// Raw count captured when the idle jump was armed.
        expected_raw_icount: u64,
        /// Unexpected later count supplied by the sim-loop callback.
        observed_raw_icount: u64,
    },
    /// The requested logical target precedes the current logical icount.
    #[error("idle advance target {target_icount} precedes current icount {current_icount}")]
    IdleAdvanceTargetRegressed {
        /// Current logical icount.
        current_icount: u64,
        /// Rejected logical target.
        target_icount: u64,
    },
    /// Projecting the logical idle target to virtual nanoseconds overflowed.
    #[error("idle advance target {target_icount} overflows at icount shift {icount_shift}")]
    IdleAdvanceTargetOverflow {
        /// Logical target being projected.
        target_icount: u64,
        /// Fixed icount shift.
        icount_shift: u8,
    },
    /// The queued QEMU target does not match the logical idle target.
    #[error(
        "idle advance target {target_icount} projects to {expected_target_virtual_ns}ns but pending request targets {pending_target_virtual_ns}ns"
    )]
    IdleAdvancePendingTargetMismatch {
        /// Logical target selected by the scheduler.
        target_icount: u64,
        /// Exact virtual target derived from the logical target.
        expected_target_virtual_ns: u64,
        /// Target retained by the queued QEMU request.
        pending_target_virtual_ns: u64,
    },
    /// QEMU rejected or mismatched the normal-main-loop completion.
    #[error("idle advance completion validation failed: {source}")]
    IdleAdvanceCompletion {
        /// Underlying queued-advance completion failure.
        source: QueuedIdleAdvanceError,
    },
    /// A logical idle target cannot be represented as a nonnegative raw offset.
    #[error("idle target {target_icount} precedes raw icount {raw_icount}")]
    IdleAdvanceOffsetUnderflow {
        /// Raw guest instruction count held across the jump.
        raw_icount: u64,
        /// Logical icount selected by the scheduler.
        target_icount: u64,
    },
    /// Adding the accumulated idle-jump offset to raw progress overflowed.
    #[error("logical icount overflows at raw icount {raw_icount} plus offset {offset}")]
    LogicalIcountOverflow {
        /// Raw retired-instruction count supplied by QEMU.
        raw_icount: u64,
        /// Accumulated logical idle-jump offset.
        offset: u64,
    },
    /// QEMU supplied null userdata to a registered live callback.
    #[error("live production callback userdata is null")]
    NullCallbackUserdata,
    /// A standard lifecycle callback named another plugin instance.
    #[error("vCPU lifecycle callback plugin id {observed} does not match {expected}")]
    PluginIdMismatch {
        /// Plugin identifier captured at registration.
        expected: QemuPluginId,
        /// Plugin identifier supplied by QEMU.
        observed: QemuPluginId,
    },
    /// QEMU named a vCPU outside the validated execution model.
    #[error("vCPU callback index {vcpu_index} is outside configured count {vcpu_count}")]
    VcpuOutOfRange {
        /// Rejected vCPU index.
        vcpu_index: u32,
        /// Validated number of vCPUs.
        vcpu_count: u32,
    },
    /// An idle/resume boundary ran before the matching vCPU initialization callback.
    #[error("vCPU callback index {vcpu_index} was not initialized")]
    VcpuNotInitialized {
        /// vCPU index that reached an out-of-order boundary.
        vcpu_index: u32,
    },
    /// A callback reported an instruction count older than its prior boundary.
    #[error("callback icount regressed from {previous_icount} to {current_icount}")]
    IcountRegressed {
        /// Most recently accepted icount.
        previous_icount: u64,
        /// Rejected older icount.
        current_icount: u64,
    },
    /// A callback reported progress beyond the scheduler's current authorization.
    #[error("callback icount {current_icount} exceeds scheduler ceiling {ceiling_icount}")]
    IcountBeyondCeiling {
        /// Rejected reached icount.
        current_icount: u64,
        /// Scheduler-published upper bound.
        ceiling_icount: u64,
    },
    /// Publishing an accepted sim-loop instruction count failed.
    #[error("publishing live callback icount failed: {source}")]
    PublishIcount {
        /// Underlying node-slot contract error.
        source: NodeSlotError,
    },
    /// Publishing the live all-idle state failed.
    #[error("publishing live callback idle state failed: {source}")]
    PublishIdle {
        /// Underlying node-slot contract error.
        source: NodeSlotError,
    },
    /// Publishing exact coordinated-pause quiescence failed.
    #[error("publishing live callback pause-quiesced state failed: {source}")]
    PublishPause {
        /// Underlying node-slot contract error.
        source: NodeSlotError,
    },
    /// QEMU rejected the native stopped-runstate handoff.
    #[error("QEMU rejected checkpoint VM-stop with status {status}")]
    CheckpointVmStopRejected {
        /// Status returned by the GPL-side QEMU capability.
        status: i32,
    },
}

impl LiveVcpuTimeCallbackError {
    pub(super) fn live_device(source: LiveDeviceCallbackError) -> Self {
        Self::LiveDevice {
            source: Box::new(source),
        }
    }
}
