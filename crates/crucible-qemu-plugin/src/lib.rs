//! SPDX-License-Identifier: GPL-2.0-only
//! `crucible-qemu-plugin` owns the in-VM QEMU plugin.
//!
//! Spec index: RFC-0010 files 11, 12.
//!
//! License boundary: this crate is GPL-2.0-only because its `cdylib` is loaded
//! into QEMU and directly implements QEMU plugin entry points and callbacks.
//! It may depend on the permissively dual-licensed `crucible-protocol` and
//! `crucible-shmem` boundary crates, but MUST NOT depend on Apache-licensed
//! Crucible host/runtime crates in production. Host/plugin communication stays
//! within the versioned socket control protocol and shared-memory process ABI.
//!
//! This L2 crate builds the `cdylib` loaded by QEMU. Later tasks will add the
//! QEMU TCG plugin entry points, time-control hooks, and device callbacks
//! specified by its indexed RFC-0010 files. It is an unsafe-boundary crate
//! because the plugin speaks QEMU's C ABI and may read guest memory.
//!
//! Module map: `abi` owns the raw QEMU plugin `cdylib` entry point and capability
//! resolution; `args` owns fail-closed `-plugin` argument parsing;
//! `boot_barrier` owns the initial scheduler-ceiling futex wait before first
//! guest instruction;
//! `handshake` owns plugin-side control-protocol version negotiation and slot
//! cross-checking;
//! `inertness` owns plugin-side sim-off load and effect assertions;
//! `deadline` owns exact virtual-clock deadline introspection; `device_io` owns
//! the virtual-time hold for in-flight device I/O; `idle_loop` owns the idle
//! callback hot-loop state machine; `inbound` owns inbound frame polling and
//! deterministic injection ordering; `network_rx` owns idle-context guest network
//! receive injection through QEMU's lossless queue; `network_tx` owns guest
//! network transmit interception and outbound ring enqueueing; `registration` owns
//! the fail-stop registration sequencer; `setup` owns descriptor mapping and setup
//! acknowledgement; `shmem_ordering` owns the plugin-side shared-memory access
//! funnel and cross-process atomic ordering contract; `teardown` owns shutdown
//! trigger proofs and post-trigger shmem sealing; `time_control` owns clock
//! ownership, authorized virtual-time advancement, and the time-control ordering
//! contract; `block_io` owns guest
//! block submit/poll request routing through the reserved block executor;
//! `ninep_io` owns raw 9p submit/poll/burst routing through the reserved 9p
//! executor; `whitebox_doorbell` owns optional white-box trap planning, guest
//! memory reads, marker stamping, host-to-guest input delivery gates, and the
//! optional app-controlled randomness request/reply path;
//! `round_robin` owns fixed-quantum vCPU rotation and per-vCPU halt tracking;
//! `preemption` owns scheduler-commanded vCPU switch and interrupt injection;
//! `runtime` owns live fail-closed installation and process-lifetime active state;
//! `vcpu_introspection` owns side-effect-free per-vCPU register and RR cursor
//! reads for N-vCPU fingerprinting;
//! `coverage` owns optional TCG-exec coverage planning and observational
//! basic-block map updates; `io_wire_fuzz` owns the pure block and 9p wire fuzz
//! target used by the ABI-conformance gate. Future modules will add live device
//! callback behavior and QEMU-facing helpers.
//!
//! Unsafe boundary discipline: exported C ABI entry points validate raw QEMU
//! pointers and delegate to safe Rust shims for time-control, callback
//! registration, and memory access. The setup path owns descriptor and mmap
//! lifetimes with typed tokens, and guest memory is represented as opaque ranges
//! read or written only through QEMU plugin API adapters.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod abi;
pub mod args;
pub mod block_io;
pub mod boot_barrier;
pub mod coverage;
pub mod deadline;
pub mod device_io;
pub mod fault_command;
pub mod fingerprint_sampler;
pub mod handshake;
pub mod idle_loop;
pub mod inbound;
pub mod inertness;
pub mod io_wire_fuzz;
pub mod network_rx;
pub mod network_tx;
pub mod ninep_io;
pub mod preemption;
pub mod raw_state_dump;
pub mod registration;
pub mod round_robin;
#[cfg(unix)]
pub mod runtime;
pub mod setup;
pub mod shmem_ordering;
pub mod teardown;
pub mod time_control;
pub mod vcpu_introspection;
pub mod whitebox_doorbell;

pub(crate) use abi::QemuPluginTargetArchitecture;
pub use abi::{
    InertDeviceCallback, MIN_SUPPORTED_VCPU_COUNT, OWNED_DEVICE_CALLBACK_KINDS,
    PluginDeviceCallbackKind, PluginLifecycleCore, PluginLifecyclePhase, PluginRuntimeApis,
    PluginStatePartition, QEMU_PLUGIN_API_VERSION, QEMU_PLUGIN_FORCE_VCPU_EXIT_SYMBOL,
    QEMU_PLUGIN_ICOUNT_RAW_SYMBOL, QEMU_PLUGIN_INSTALL_ERROR, QEMU_PLUGIN_INSTALL_OK,
    QEMU_PLUGIN_INSTALL_SYMBOL, QEMU_PLUGIN_REGISTER_9P_CB_SYMBOL,
    QEMU_PLUGIN_REGISTER_ACCELERATOR_CB_SYMBOL, QEMU_PLUGIN_REGISTER_BLK_CB_SYMBOL,
    QEMU_PLUGIN_REGISTER_BLK_EVENT_CB_SYMBOL, QEMU_PLUGIN_REGISTER_BLK_WAIT_CB_SYMBOL,
    QEMU_PLUGIN_REGISTER_ENTRYPOINT_SYMBOL, QEMU_PLUGIN_REGISTER_SIM_SHMEM_DISPATCH_CB_SYMBOL,
    QEMU_PLUGIN_REGISTER_VCPU_IDLE_RESUME_CB_SYMBOL, QEMU_PLUGIN_REGISTER_VCPU_INIT_CB_SYMBOL,
    QEMU_PLUGIN_REGISTER_WAKE_FD_SYMBOL, QEMU_PLUGIN_REQUEST_SHUTDOWN_SYMBOL,
    QEMU_PLUGIN_REQUEST_VMSTOP_SYMBOL, QEMU_PLUGIN_SET_PROCESS_GENERATION_SYMBOL,
    QEMU_PLUGIN_VERSION_SYMBOL, QemuAcceleratorPollCbFn, QemuAcceleratorRestoreCbFn,
    QemuAcceleratorSubmitCbFn, QemuAcceleratorWaitCbFn, QemuBlkEventCommitCbFn,
    QemuBlkEventPollCbFn, QemuBlkPollCbFn, QemuBlkSubmitCbFn, QemuBlkTransportRestoreCbFn,
    QemuBlkTransportSaveCbFn, QemuBlkWaitCbFn, QemuForceVcpuExitFn, QemuIcountRawFn,
    QemuNinePBurstCbFn, QemuNinePPollCbFn, QemuNinePSubmitCbFn, QemuPluginAbiError,
    QemuPluginExecutionModel, QemuPluginId, QemuPluginInfo, QemuRegisterAcceleratorCbFn,
    QemuRegisterBlkCbFn, QemuRegisterBlkEventCbFn, QemuRegisterBlkWaitCbFn, QemuRegisterNinePCbFn,
    QemuRegisterSimShmemDispatchCbFn, QemuRegisterTcgExecCbFn, QemuRegisterVcpuIdleResumeCbFn,
    QemuRegisterVcpuInitCbFn, QemuRegisterWakeFdFn, QemuRequestShutdownFn, QemuRequestVmstopFn,
    QemuSetProcessGenerationFn, QemuSimShmemMaxAdvanceIcountCbFn, QemuSimShmemPublishIcountCbFn,
    QemuTcgExecCbFn, QemuTcgThreading, QemuVcpuIdleResumeCbFn, QemuVcpuSimpleCbFn,
    RegisteredDeviceCallbacks, execution_model_from_qemu_info, install_inert_scaffold,
    install_inert_scaffold_from_qemu_info, install_required_deadline_scaffold,
    install_required_deadline_scaffold_from_qemu_info, install_required_preemption_scaffold,
    install_required_preemption_scaffold_from_qemu_info, install_required_runtime_api_scaffold,
    install_required_runtime_api_scaffold_from_qemu_info,
    install_required_time_capability_scaffold,
    install_required_time_capability_scaffold_from_qemu_info,
    install_required_vcpu_introspection_scaffold,
    install_required_vcpu_introspection_scaffold_from_qemu_info, qemu_plugin_install,
    qemu_plugin_version, resolve_qemu_advance_time_ns_symbol, resolve_qemu_clock_deadline_symbol,
    resolve_qemu_force_vcpu_exit_symbol, resolve_qemu_icount_raw_symbol,
    resolve_qemu_inject_preemption_symbol, resolve_qemu_read_vcpu_regs_symbol,
    resolve_qemu_register_9p_cb_symbol, resolve_qemu_register_accelerator_cb_symbol,
    resolve_qemu_register_blk_cb_symbol, resolve_qemu_register_blk_event_cb_symbol,
    resolve_qemu_register_blk_wait_cb_symbol, resolve_qemu_register_sim_shmem_dispatch_cb_symbol,
    resolve_qemu_register_tcg_exec_cb_symbol, resolve_qemu_register_time_advance_cb_symbol,
    resolve_qemu_register_vcpu_idle_resume_cb_symbol, resolve_qemu_register_vcpu_init_cb_symbol,
    resolve_qemu_register_wake_fd_symbol, resolve_qemu_request_shutdown_symbol,
    resolve_qemu_request_time_control_symbol, resolve_qemu_request_vmstop_symbol,
    resolve_qemu_rr_cursor_symbol, resolve_qemu_set_process_generation_symbol,
    validate_install_boundary,
};
pub use args::{
    PLUGIN_ARG_APP_RANDOM_CAP, PLUGIN_ARG_APP_RANDOM_NODE, PLUGIN_ARG_APP_RANDOM_SEED,
    PLUGIN_ARG_COVERAGE, PLUGIN_ARG_FAULT_NODE_HASH, PLUGIN_ARG_FINGERPRINT,
    PLUGIN_ARG_PROCESS_GENERATION, PLUGIN_ARG_SHMEMFD, PLUGIN_ARG_SIMFD, PLUGIN_ARG_SLOT,
    PLUGIN_ARG_WAKEFD, PLUGIN_ARG_WHITEBOX, PLUGIN_ARG_WHITEBOX_SETUP, PluginAppRandomConfig,
    PluginArgs, PluginArgsParseError, PluginInheritedFds, PluginStateDumpConfig, PluginSwitch,
    WHITEBOX_SETUP_AARCH64_HLT_UNCLAIMED_V1, WHITEBOX_SETUP_X86_PORT_UNCLAIMED_V1,
    WhiteboxSetupAttestation,
};
pub use block_io::{
    BlockGuestCompletion, BlockGuestCompletionError, BlockInboundRing, BlockIoError,
    BlockOperation, BlockOutboundRing, BlockPoll, BlockRequest, BlockRequestIdentity,
    BlockRequestToken, BlockResponse, BlockResponseErrorCode, BlockResponseStatus, BlockSubmit,
    BlockTransportEvent, BlockTransportPending, BlockTransportRequestIds, BlockTransportReset,
    BlockTransportResolved, BlockTransportUnadmitted, BlockTransportUndelivered, BlockWireError,
    PendingBlockTransportEvent, PluginBlockIo, handle_block_poll_callback,
    handle_block_submit_callback,
};
pub use boot_barrier::{
    BOOT_BARRIER_FIRST_GUEST_ICOUNT, BootBarrierError, BootBarrierRelease, BootBarrierWait,
    PluginBootBarrier,
};
pub use coverage::{
    CoverageBlockEvent, CoverageCallback, CoverageCapabilities, CoverageError, CoverageMap,
    CoverageObservation, CoverageRegistrationPlan, CoverageSink, CoverageSinkError,
    DEFAULT_COVERAGE_MAP_ENTRIES, PluginCoverage, QEMU_PLUGIN_ICOUNT_AT_TB_ENTRY_SYMBOL,
    QEMU_PLUGIN_INSN_SIZE_SYMBOL, QEMU_PLUGIN_REGISTER_FLUSH_CB_SYMBOL,
    QEMU_PLUGIN_REGISTER_TCG_EXEC_CB_SYMBOL, QEMU_PLUGIN_REGISTER_VCPU_TB_EXEC_COND_CB_SYMBOL,
    QEMU_PLUGIN_REGISTER_VCPU_TB_TRANS_CB_SYMBOL, QEMU_PLUGIN_SCOREBOARD_FREE_SYMBOL,
    QEMU_PLUGIN_SCOREBOARD_NEW_SYMBOL, QEMU_PLUGIN_TB_GET_INSN_SYMBOL,
    QEMU_PLUGIN_TB_N_INSNS_SYMBOL, QEMU_PLUGIN_TB_VADDR_SYMBOL, QEMU_PLUGIN_U64_SET_SYMBOL,
    QemuBasicBlockCoverageApis, QemuIcountAtTbEntryFn, QemuInsnSizeFn, QemuPluginInsn,
    QemuPluginScoreboard, QemuPluginScoreboardFreeFn, QemuPluginScoreboardNewFn,
    QemuPluginSimpleCbFn, QemuPluginTb, QemuPluginU64, QemuPluginU64SetFn, QemuRegisterFlushCbFn,
    QemuRegisterVcpuTbExecCondCbFn, QemuRegisterVcpuTbTransCbFn, QemuTbGetInsnFn, QemuTbNInsnsFn,
    QemuTbVaddrFn, QemuVcpuTbExecCbFn, QemuVcpuTbTransCbFn, fold_basic_block_pc,
    handle_coverage_exec_callback,
};
pub use deadline::{
    ClockDeadlineSource, DeadlineFallbackPolicy, ExactDeadlineError, ExactDeadlineIntrospection,
    ExactDeadlineReader, ExactDeadlineReport, PerVcpuDeadlineReport,
    QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL, QemuClockDeadlineFn, aggregate_multi_vcpu_deadline,
};
pub use device_io::{
    DeviceIoBurstState, DeviceIoFreezeError, DeviceIoRequestOutcome, DeviceIoRequestRelease,
    DeviceIoRequestToken, PluginDeviceIoFreeze,
};
pub use fault_command::{
    FaultCommandBridgeError, QEMU_PLUGIN_CRUCIBLE_FAULT_CANCEL_SYMBOL,
    QEMU_PLUGIN_CRUCIBLE_FAULT_CAPABILITIES_SYMBOL, QEMU_PLUGIN_CRUCIBLE_FAULT_PEEK_SYMBOL,
    QEMU_PLUGIN_CRUCIBLE_FAULT_POLL_SYMBOL, QEMU_PLUGIN_CRUCIBLE_FAULT_REGISTER_BIND_SYMBOL,
    QEMU_PLUGIN_CRUCIBLE_FAULT_REGISTER_MANIFEST_SYMBOL, QEMU_PLUGIN_CRUCIBLE_FAULT_SUBMIT_SYMBOL,
};
pub use fingerprint_sampler::{
    FINGERPRINT_FAILURE_DEVICE_STATE, FINGERPRINT_FAILURE_DEVICE_STATE_SCHEMA,
    FINGERPRINT_FAILURE_RAM, FingerprintSamplerError, PluginFingerprintDigester,
    PluginFingerprintSampling, QEMU_PLUGIN_CRUCIBLE_DEVICE_STATE_SCHEMA_SHA256_SYMBOL,
    QEMU_PLUGIN_CRUCIBLE_DEVICE_STATE_SHA256_SYMBOL,
    QEMU_PLUGIN_CRUCIBLE_FINGERPRINT_CAPTURE_FREE_SYMBOL,
    QEMU_PLUGIN_CRUCIBLE_FINGERPRINT_CAPTURE_SYMBOL, QEMU_PLUGIN_CRUCIBLE_GUEST_RAM_SHA256_SYMBOL,
    QEMU_PLUGIN_CRUCIBLE_SHA256_BYTES_SYMBOL, QemuDigestFn, QemuFingerprintCaptureFn,
    QemuFingerprintCaptureFreeFn, QemuSha256BytesFn, assemble_fingerprint_sample,
};
pub use handshake::{
    PluginControlHandshake, PluginHandshakeError, perform_plugin_handshake,
    plugin_handshake_config, validate_plugin_handshake,
};
pub use idle_loop::{
    IdleHotLoopError, IdleHotLoopResult, IdleParkRequest, IdleWaitOutcome, IdleWakeCause,
    IdleWakePlan, PluginIdleHotLoop, compute_idle_wake_plan, timer_deadline_icount,
};
pub use inbound::{InboundFrameBatch, InboundFrameError, InboundFrameRing, PluginInboundFrames};
pub use inertness::{
    PluginInertnessError, PluginInertnessObservation, PluginInertnessReport,
    PluginPatchCapabilityCalls, PluginSimulationMode, assert_plugin_inert,
};
pub use io_wire_fuzz::{
    IO_WIRE_FUZZ_REGRESSION_CORPUS, IoWireFuzzCase, IoWireFuzzChannel, IoWireFuzzOutcome,
    run_io_wire_fuzz_target,
};
pub use network_rx::{
    LosslessNetworkRxQueue, NetworkRxError, NetworkRxInjection, NetworkRxQueueError,
    NetworkRxQueueOperation, PluginNetworkRx, QEMU_PLUGIN_NET_CAN_RECEIVE_SYMBOL,
    QEMU_PLUGIN_NET_FLUSH_SYMBOL, QEMU_PLUGIN_NET_SEND_SYMBOL, QemuLosslessNetworkRxQueue,
    QemuPluginNetCanReceiveFn, QemuPluginNetFlushFn, QemuPluginNetSendFn,
    handle_network_rx_idle_callback, resolve_qemu_net_can_receive_symbol,
    resolve_qemu_net_flush_symbol, resolve_qemu_net_send_symbol,
};
pub use network_tx::{
    NetworkTxEnqueue, NetworkTxError, NetworkTxRing, PluginNetworkTx,
    QEMU_PLUGIN_REGISTER_NET_TX_CB_SYMBOL, QemuNetTxCbFn, QemuRegisterNetTxCbFn,
    handle_network_tx_callback, resolve_qemu_register_net_tx_cb_symbol,
};
pub use ninep_io::{
    NinePGuestCompletion, NinePGuestCompletionError, NinePInboundRing, NinePIoError,
    NinePOutboundRing, NinePPoll, NinePRequest, NinePRequestToken, NinePResponse, NinePSubmit,
    NinePWireError, NinePWireHandlerOutcome, NinePWireMessage, PluginNinePIo,
    handle_9p_burst_done_callback, handle_9p_burst_start_callback, handle_9p_poll_callback,
    handle_9p_submit_callback, handle_ninep_wire_fuzz_message,
};
pub use preemption::{
    DeterministicIpiDelivery, PluginPreemptionApplication, PluginPreemptionDecision,
    PluginPreemptionInjector, PluginPreemptionKind, PreemptionError, PreemptionWindow,
    QEMU_PLUGIN_INJECT_PREEMPTION_SYMBOL, QEMU_PREEMPTION_KIND_INTERRUPT_AT,
    QEMU_PREEMPTION_KIND_VCPU_SWITCH, QEMU_PREEMPTION_UNUSED_ARG, QemuInjectPreemptionFn,
    QemuPreemptionCommand, plan_deterministic_ipi_delivery,
};
pub use raw_state_dump::{PluginRawStateDump, PluginRawStateDumpError};
pub use registration::{
    PluginCallbackCapabilities, PluginRegistrationFailure, PluginRegistrationReady,
    PluginRegistrationSequence, PluginRegistrationSequenceError,
};
pub use round_robin::{
    RoundRobinConfig, RoundRobinError, RoundRobinRunState, RoundRobinTurn, VcpuHaltTracker,
    compute_all_halted_idle_wake_plan,
};
#[cfg(unix)]
pub use runtime::{
    LiveDeviceCallbackError, LiveVcpuTimeCallbackError, OwnedCallbackRegistrationError,
    PluginRuntimeInstallError, PluginRuntimeOwner, REQUIRED_OWNED_CALLBACK_FAMILIES,
    RequiredOwnedCallbacksRegistered, active_runtime_is_published,
};
pub use setup::PluginReadySetupAck;
#[cfg(unix)]
pub use setup::{
    ArmedWakeFd, PluginSetupBootBarrierError, PluginSetupCompletion, PluginSetupError,
    PluginSetupFailureStage, RegisteredWakeFd, WakeFdArmError, WakeFdRegisterError,
    prepare_setup_completion, receive_and_prepare_setup_completion, receive_setup_with_descriptors,
    send_callback_registration_failure_ack, send_ready_setup_ack,
};
pub use shmem_ordering::PluginShmemOrdering;
pub use teardown::{
    PluginHostQuit, PluginQemuShutdown, PluginQemuShutdownError, PluginShmemAccess,
    PluginShutdownRequested, PluginTeardown, PluginTeardownComplete, PluginTeardownError,
    PluginTeardownTrigger,
};
pub use time_control::{
    CANONICAL_TIME_CONTROL_REGISTRATION_ORDER, MAX_PLUGIN_ICOUNT_SHIFT, PendingIdleAdvance,
    PluginClockAdvance, PluginClockAdvanceSource, PluginClockError, PluginRegistrationStep,
    PluginTimeControlOwnership, PluginTimeControlRequestError, PluginVirtualClock,
    QEMU_PLUGIN_ADVANCE_TIME_NS_SYMBOL, QEMU_PLUGIN_HAS_TIME_CONTROL_SYMBOL,
    QEMU_PLUGIN_REGISTER_TIME_ADVANCE_CB_SYMBOL, QEMU_PLUGIN_REQUEST_TIME_CONTROL_SYMBOL,
    QEMU_PLUGIN_UPDATE_NS_SYMBOL, QemuAdvanceTimeNsFn, QemuRegisterTimeAdvanceCbFn,
    QemuRequestTimeControlFn, QemuTimeAdvanceCompletionCbFn, QueuedIdleAdvance,
    QueuedIdleAdvanceError, SchedulerAuthorizedIdleJump, SchedulerCeiling, TimeAdvanceCompletion,
    TimeControlRegistrationError, TimeControlRegistrationPlan,
};
pub use vcpu_introspection::{
    MAX_VCPU_REGISTER_FILE_BYTES, PLUGIN_REGISTER_DIGEST_BYTES, PluginNvcpuFingerprintInputs,
    PluginRoundRobinCursor, PluginVcpuIntrospector, PluginVcpuRegisterDigest,
    QEMU_PLUGIN_CRUCIBLE_GET_VCPU_REGISTERS_SYMBOL, QEMU_PLUGIN_CRUCIBLE_READ_VCPU_REGISTER_SYMBOL,
    QEMU_PLUGIN_CRUCIBLE_RR_CURRENT_VCPU_SYMBOL, QEMU_PLUGIN_CRUCIBLE_RR_CURSOR_POSITION_SYMBOL,
    QEMU_PLUGIN_CRUCIBLE_RR_SWITCH_QUANTUM_SYMBOL, QEMU_PLUGIN_READ_VCPU_REGS_SYMBOL,
    QEMU_PLUGIN_RR_CURSOR_SYMBOL, QemuReadRrCursorFn, QemuReadVcpuRegsFn, QemuRoundRobinCursor,
    VcpuIntrospectionError, digest_register_file,
};
pub use whitebox_doorbell::{
    AppRandomDecisionError, AppRandomDecisionRecord, AppRandomDecisionSource,
    AppRandomDecodeDiagnostic, AppRandomDecodeDiagnosticKind, AppRandomDoorbellError,
    AppRandomDoorbellOutcome, AppRandomDoorbellRequest, AppRandomDoorbellService,
    GOLDEN_WHITEBOX_DOORBELL_FRAME_VECTORS, GOLDEN_WHITEBOX_MARKER_PAYLOAD_VECTORS,
    GuestMemoryAddressSpace, GuestMemoryRange, GuestMemoryReadError, GuestMemoryReader,
    PluginWhiteboxDoorbell, QEMU_PLUGIN_DOORBELL_EXEC_CB_SYMBOL,
    QEMU_PLUGIN_DOORBELL_TRANSLATION_SYMBOL, QEMU_PLUGIN_GUEST_MEMORY_READ_SYMBOL,
    QEMU_PLUGIN_GUEST_MEMORY_WRITE_SYMBOL, QEMU_PLUGIN_READ_REGISTER_SYMBOL,
    QEMU_PLUGIN_REGISTER_DOORBELL_TRAP_SYMBOL, WHITEBOX_APP_RANDOM_MAX_WIDTH_BYTES,
    WHITEBOX_DOORBELL_AARCH64_ABI, WHITEBOX_DOORBELL_AARCH64_HLT_BYTES,
    WHITEBOX_DOORBELL_AARCH64_RESERVED_IMMEDIATE, WHITEBOX_DOORBELL_ABIS,
    WHITEBOX_DOORBELL_FRAME_HEADER_LEN, WHITEBOX_DOORBELL_FRAME_MAGIC,
    WHITEBOX_DOORBELL_FRAME_REGENERATION_RULE, WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION,
    WHITEBOX_DOORBELL_KIND_ASSERTION, WHITEBOX_DOORBELL_KIND_COVERAGE,
    WHITEBOX_DOORBELL_KIND_EVENT, WHITEBOX_DOORBELL_KIND_LIFECYCLE,
    WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST, WHITEBOX_DOORBELL_LIFECYCLE_SETUP_COMPLETE,
    WHITEBOX_DOORBELL_LIFECYCLE_TEST_DONE, WHITEBOX_DOORBELL_MARKER_KIND_COUNT,
    WHITEBOX_DOORBELL_PROTOCOL_VERSION, WHITEBOX_DOORBELL_RANDOM_REQUEST_MAX_WIDTH_BYTES,
    WHITEBOX_DOORBELL_X86_64_ABI, WHITEBOX_DOORBELL_X86_64_OUT_IMM8_AL_BYTES,
    WHITEBOX_DOORBELL_X86_64_RESERVED_PORT, WHITEBOX_GUEST_MEMORY_ADDRESSING_UNRESOLVED,
    WHITEBOX_GUEST_MEMORY_VADDR_SPIKE_CHECK, WhiteboxAssertionMarkerBody,
    WhiteboxAssertionMarkerFlavor, WhiteboxCoverageMarkerBody, WhiteboxDoorbellAbi,
    WhiteboxDoorbellArchitecture, WhiteboxDoorbellCapabilities, WhiteboxDoorbellCollision,
    WhiteboxDoorbellDecodeDiagnostic, WhiteboxDoorbellDecodeDiagnosticKind, WhiteboxDoorbellError,
    WhiteboxDoorbellFrame, WhiteboxDoorbellFrameDecodeError, WhiteboxDoorbellFrameEncodeError,
    WhiteboxDoorbellFrameGoldenVector, WhiteboxDoorbellInstruction, WhiteboxDoorbellMarkerKind,
    WhiteboxDoorbellPayloadSource, WhiteboxDoorbellRegistrationPlan, WhiteboxDoorbellSetupOutcome,
    WhiteboxDoorbellSetupResources, WhiteboxDoorbellSetupValidation, WhiteboxDoorbellTrap,
    WhiteboxDoorbellTrapAbi, WhiteboxDoorbellTrapEvent, WhiteboxEventMarkerBody,
    WhiteboxGuestInput, WhiteboxGuestInputCapability, WhiteboxGuestInputInjection,
    WhiteboxGuestInputOutcome, WhiteboxGuestInputWriteError, WhiteboxGuestInputWriter,
    WhiteboxGuestMemoryAddressingResolution, WhiteboxLifecycleMarkerEvent, WhiteboxMarker,
    WhiteboxMarkerDetail, WhiteboxMarkerPayload, WhiteboxMarkerPayloadDecodeError,
    WhiteboxMarkerPayloadEncodeError, WhiteboxMarkerPayloadGoldenVector, WhiteboxMarkerSink,
    WhiteboxMarkerSinkError, WhiteboxPayloadAddressingMode, WhiteboxRandomRequestBody,
    decode_whitebox_marker_payload, encode_aarch64_hlt_instruction, encode_whitebox_doorbell_frame,
    encode_whitebox_marker_frame, encode_whitebox_marker_payload_body,
    encode_x86_64_out_imm8_al_instruction, handle_whitebox_app_random_callback,
    handle_whitebox_doorbell_callback, handle_whitebox_guest_input_callback,
    whitebox_doorbell_abi_for_architecture,
};
