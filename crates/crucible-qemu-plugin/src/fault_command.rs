//! Live shared-memory to QEMU fault-command bridge.
//!
//! The Apache host publishes only the dual-licensed byte protocol. This GPL
//! module validates and copies that protocol, translates scheduler-logical
//! instruction coordinates to QEMU's raw retired-instruction space, and calls
//! the closed QEMU fault registry through resolved C symbols. Results take the
//! reverse path and are re-encoded into the public shared-memory ABI.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr::NonNull;

use crucible_shmem::{
    DequeuedFaultCommand, FAULT_CAPABILITY_FEATURE_GUEST_CLOCK,
    FAULT_CAPABILITY_FEATURE_HARDWARE_ERROR, FAULT_CAPABILITY_FEATURE_INSTRUCTION,
    FAULT_CAPABILITY_FEATURE_INTERRUPT, FAULT_CAPABILITY_FEATURE_REGISTER_MUTATION,
    FAULT_COMMAND_FLAG_PREPARE_ONLY, FAULT_COMMAND_SEMANTIC_VERSION,
    FAULT_REGISTER_CAPABILITY_IMPULSE, FAULT_TARGET_MANIFEST_QUERY_V1_BYTES, FaultAbiError,
    FaultAcceleratorCapabilityManifestV1, FaultAcceleratorCapabilityRowV1, FaultBoundaryPhase,
    FaultCapabilityRowV1, FaultCapabilityScope, FaultClockCapabilityManifestV1,
    FaultClockCapabilityRowV1, FaultClockEvidenceV1, FaultClockObservationV1, FaultCommandHeaderV1,
    FaultCommandKind, FaultCommandSlotV1, FaultEventHeaderV1, FaultEventOutcomeV1,
    FaultEventSlotV1, FaultExceptionEvidenceV1, FaultHardwareErrorCapabilityManifestV1,
    FaultHardwareErrorCapabilityRowV1, FaultHardwareErrorClassV1, FaultHardwareErrorMechanismV1,
    FaultHardwareErrorRecordKindV1, FaultInstructionEvidenceOutcomeV1, FaultInstructionEvidenceV1,
    FaultInstructionMutationKindV1, FaultInstructionPortIoEvidenceV1,
    FaultInterruptCapabilityManifestV1, FaultInterruptCapabilityRowV1,
    FaultInterruptDeliveryDropV1, FaultInterruptFamilyV1, FaultInterruptPolarityV1,
    FaultInterruptTriggerV1, FaultPayloadArenaHeader, FaultRegisterCapabilityManifestV1,
    FaultRegisterCapabilityRowV1, FaultRegisterGroupV1, FaultRegisterMutationEvidenceV1,
    FaultRegisterMutationKindV1, FaultResultHeaderV1, FaultResultSlotV1, FaultResultStatus,
    FaultSystemCapabilityManifestV1, FaultTargetManifestKind, FaultTargetManifestQueryV1,
    FaultTerminalEvidenceV1, FaultTransportError, HARD_FAULT_PAYLOAD_BYTES,
    MappedFaultCommandTransportMut, MappedFaultEventTransportMut, MappedFaultResultTransportMut,
    MappedSetupRegion, MappedSetupRegionAccessError, NodeFaultOperationV1, NodeFaultPayloadV1,
    NodeFaultTargetKindV1, RingHeader, can_enqueue_fault_event, can_enqueue_fault_result,
    dequeue_fault_command, encode_fault_capability_manifest, enqueue_fault_event,
    enqueue_fault_result, fault_capability_manifest_digest, fault_object_id_hash_v1,
    fault_register_cpu_model_digest_v1, fault_register_manifest_digest_v1, node_fault_field,
};
use sha2::Digest as _;
use thiserror::Error;

/// QEMU symbol that copies the immutable sorted fault capability registry.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_CAPABILITIES_SYMBOL: &str =
    "qemu_plugin_crucible_fault_capabilities";
/// QEMU symbol that copies and arms one validated fault command.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_SUBMIT_SYMBOL: &str = "qemu_plugin_crucible_fault_submit";
/// QEMU symbol that cancels one not-yet-applied command.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_CANCEL_SYMBOL: &str = "qemu_plugin_crucible_fault_cancel";
/// QEMU symbol that non-destructively describes the oldest completed result.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_PEEK_SYMBOL: &str = "qemu_plugin_crucible_fault_peek";
/// QEMU symbol that copies one completed fault result.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_POLL_SYMBOL: &str = "qemu_plugin_crucible_fault_poll";
/// QEMU symbol that non-destructively describes the oldest rule event.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_EVENT_PEEK_SYMBOL: &str =
    "qemu_plugin_crucible_fault_event_peek";
/// QEMU symbol that reports the mandatory restored-event envelope schema.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_EVENT_ENVELOPE_VERSION_SYMBOL: &str =
    "qemu_plugin_crucible_fault_event_envelope_version";
/// QEMU symbol that copies and consumes one rule event.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_EVENT_POLL_SYMBOL: &str =
    "qemu_plugin_crucible_fault_event_poll";
/// QEMU symbol that copies architecture-owned register target rows.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_REGISTER_MANIFEST_SYMBOL: &str =
    "qemu_plugin_crucible_fault_register_manifest";
/// QEMU symbol that seals one public identity-to-private-register binding.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_REGISTER_BIND_SYMBOL: &str =
    "qemu_plugin_crucible_fault_register_bind";
/// QEMU symbol that binds the public register architecture identity.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_REGISTER_BIND_ARCHITECTURE_SYMBOL: &str =
    "qemu_plugin_crucible_fault_register_bind_architecture";
/// QEMU symbol that seals the complete register identity map.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_REGISTER_BINDINGS_SEAL_SYMBOL: &str =
    "qemu_plugin_crucible_fault_register_bindings_seal";
/// QEMU symbol that copies the immutable instruction decoder manifest.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_INSTRUCTION_MANIFEST_SYMBOL: &str =
    "qemu_plugin_crucible_fault_instruction_manifest";
/// QEMU symbol that copies architecture-owned interrupt target rows.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_INTERRUPT_MANIFEST_SYMBOL: &str =
    "qemu_plugin_crucible_fault_interrupt_manifest";
/// QEMU symbol that binds one public interrupt identity row.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_INTERRUPT_BIND_SYMBOL: &str =
    "qemu_plugin_crucible_fault_interrupt_bind";
/// QEMU symbol that seals every interrupt identity row.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_INTERRUPT_BINDINGS_SEAL_SYMBOL: &str =
    "qemu_plugin_crucible_fault_interrupt_bindings_seal";
/// QEMU symbol that copies architecture and platform hardware-error rows.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_HARDWARE_ERROR_MANIFEST_SYMBOL: &str =
    "qemu_plugin_crucible_fault_hardware_error_manifest";
/// QEMU symbol that binds one public hardware-error identity row.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_HARDWARE_ERROR_BIND_SYMBOL: &str =
    "qemu_plugin_crucible_fault_hardware_error_bind";
/// QEMU symbol that seals every hardware-error identity row.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_HARDWARE_ERROR_BINDINGS_SEAL_SYMBOL: &str =
    "qemu_plugin_crucible_fault_hardware_error_bindings_seal";
/// QEMU symbol that copies realized guest-clock source rows.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_CLOCK_MANIFEST_SYMBOL: &str =
    "qemu_plugin_crucible_fault_clock_manifest";
/// QEMU symbol that binds one guest-clock source identity.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_CLOCK_BIND_SYMBOL: &str =
    "qemu_plugin_crucible_fault_clock_bind";
/// QEMU symbol that seals every guest-clock source identity.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_CLOCK_BINDINGS_SEAL_SYMBOL: &str =
    "qemu_plugin_crucible_fault_clock_bindings_seal";
/// QEMU symbol that copies realized accelerator-device rows.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_ACCELERATOR_MANIFEST_SYMBOL: &str =
    "qemu_plugin_crucible_fault_accelerator_manifest";
/// QEMU symbol that returns the final build, patch, shmem, and VMState identity.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_SYSTEM_MANIFEST_SYMBOL: &str =
    "qemu_plugin_crucible_fault_system_manifest";

const CAPABILITIES_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_fault_capabilities\0";
const SUBMIT_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_fault_submit\0";
const CANCEL_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_fault_cancel\0";
const PEEK_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_fault_peek\0";
const POLL_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_fault_poll\0";
const EVENT_PEEK_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_fault_event_peek\0";
const EVENT_ENVELOPE_VERSION_SYMBOL_C: &[u8] =
    b"qemu_plugin_crucible_fault_event_envelope_version\0";
const EVENT_POLL_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_fault_event_poll\0";
const REGISTER_MANIFEST_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_fault_register_manifest\0";
const REGISTER_BIND_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_fault_register_bind\0";
const REGISTER_BIND_ARCHITECTURE_SYMBOL_C: &[u8] =
    b"qemu_plugin_crucible_fault_register_bind_architecture\0";
const REGISTER_BINDINGS_SEAL_SYMBOL_C: &[u8] =
    b"qemu_plugin_crucible_fault_register_bindings_seal\0";
const INSTRUCTION_MANIFEST_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_fault_instruction_manifest\0";
const INTERRUPT_MANIFEST_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_fault_interrupt_manifest\0";
const INTERRUPT_BIND_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_fault_interrupt_bind\0";
const INTERRUPT_BINDINGS_SEAL_SYMBOL_C: &[u8] =
    b"qemu_plugin_crucible_fault_interrupt_bindings_seal\0";
const HARDWARE_ERROR_MANIFEST_SYMBOL_C: &[u8] =
    b"qemu_plugin_crucible_fault_hardware_error_manifest\0";
const HARDWARE_ERROR_BIND_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_fault_hardware_error_bind\0";
const HARDWARE_ERROR_BINDINGS_SEAL_SYMBOL_C: &[u8] =
    b"qemu_plugin_crucible_fault_hardware_error_bindings_seal\0";
const CLOCK_MANIFEST_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_fault_clock_manifest\0";
const CLOCK_BIND_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_fault_clock_bind\0";
const CLOCK_BINDINGS_SEAL_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_fault_clock_bindings_seal\0";
const ACCELERATOR_MANIFEST_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_fault_accelerator_manifest\0";
const SYSTEM_MANIFEST_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_fault_system_manifest\0";
const CAPABILITY_HASH_DOMAIN: &[u8] = b"crucible.qemu-fault-capability.v1\0";
const EXPECTED_QEMU_BUILD_ID: Option<&str> = option_env!("CRUCIBLE_QEMU_BUILD_ID");
const EXPECTED_QEMU_PATCH_SERIES_HASH: Option<&str> =
    option_env!("CRUCIBLE_QEMU_PATCH_SERIES_HASH");
const EXPECTED_SHMEM_HEADER_HASH: Option<&str> = option_env!("CRUCIBLE_SHMEM_HEADER_HASH");

#[repr(C)]
#[derive(Clone, Copy)]
struct QemuFaultCommand {
    abi_major: u16,
    abi_minor: u16,
    command_kind: u16,
    command_flags: u16,
    phase: u16,
    reserved: u16,
    semantic_version: u32,
    command_sequence: u64,
    target_node_hash: [u8; 32],
    target_icount: u64,
    authorization_ceiling_icount: u64,
    binding_hash: [u8; 32],
    opportunity_hash: [u8; 32],
    expected_precondition_hash: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct QemuFaultResult {
    command_kind: u16,
    status: u16,
    phase: u16,
    reserved: u16,
    semantic_version: u32,
    capability_version: u32,
    command_sequence: u64,
    observed_icount: u64,
    applied_icount: u64,
    before_hash: [u8; 32],
    after_hash: [u8; 32],
    evidence_hash: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct QemuFaultEvent {
    command_kind: u16,
    outcome: u16,
    model_phase: u16,
    target_kind: u16,
    evidence_length: u32,
    event_sequence: u64,
    rule_command_sequence: u64,
    observed_icount: u64,
    generation: u64,
    binding_hash: [u8; 32],
    opportunity_hash: [u8; 32],
    action_hash: [u8; 32],
    target_hash: [u8; 32],
    before_hash: [u8; 32],
    after_hash: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct QemuFaultCapability {
    command_kind: u16,
    scope: u16,
    semantic_version: u32,
    phase_mask: u32,
    maximum_payload_bytes: u32,
    maximum_pending_commands: u32,
    required_feature_bits: u64,
    name: *const c_char,
    payload_schema: *const c_char,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct QemuFaultRegisterCapability {
    numeric_id: u32,
    width_bits: u32,
    group: u16,
    reserved: u16,
    model_phase_mask: u64,
    side_effects: u32,
    capabilities: u32,
    name: *const c_char,
    writable_mask: *const u8,
    reserved_mask: *const u8,
    ignored_mask: *const u8,
    read_only_mask: *const u8,
    mask_bytes: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct QemuFaultInterruptCapability {
    family: u16,
    trigger: u16,
    polarity: u16,
    delivery_drop: u16,
    vector_start: u32,
    vector_end: u32,
    replacement_vector_start: u32,
    replacement_vector_end: u32,
    priority: u16,
    vmstate: u8,
    reserved: u8,
    model_phase_mask: u64,
    id: *const c_char,
    controller: *const c_char,
    source: *const c_char,
    controller_version: *const c_char,
    target_vcpus: *const u32,
    target_vcpu_count: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct QemuFaultHardwareErrorCapability {
    record_kind: u16,
    error_class: u16,
    mechanism: u16,
    visibility_mask: u16,
    bank_number: u32,
    bank_count: u32,
    vector: u32,
    reserved0: u32,
    status_required: u64,
    status_allowed: u64,
    syndrome_required: u64,
    syndrome_allowed: u64,
    model_phase_mask: u64,
    privilege_mask: u16,
    corrected: u8,
    maskable: u8,
    vmstate: u8,
    reserved1: u8,
    id: *const c_char,
    bank: *const c_char,
    channel: *const c_char,
    rank: *const c_char,
    firmware: *const c_char,
    state: *const c_char,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct QemuFaultClockCapability {
    source_kind: u16,
    architecture: u16,
    base_domain: u16,
    timer_relationship: u16,
    width_bits: u32,
    flags: u32,
    frequency_numerator: u64,
    frequency_denominator: u64,
    model_phase_mask: u64,
    vmstate: u8,
    monotonicity: u8,
    reserved: [u8; 6],
    id: *const c_char,
    implementation: *const c_char,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct QemuFaultAcceleratorCapability {
    class_mask: u16,
    fault_family_mask: u16,
    queue_start: u16,
    queue_end: u16,
    queue_depth: u32,
    maximum_input_bytes: u32,
    maximum_output_bytes: u32,
    device_memory_bytes: u64,
    ecc_mode_mask: u32,
    job_kind_count: u32,
    vmstate: u8,
    reserved: [u8; 7],
    id: *const c_char,
    implementation: *const c_char,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct QemuFaultSystemManifest {
    semantic_version: u32,
    vmstate_format_version: u32,
    vmstate_section_count: u32,
    reserved: u32,
    vmstate_sections_sha256: [u8; 32],
    system_capability: *const c_char,
    vmstate_capability: *const c_char,
    qemu_build_id: *const c_char,
    qemu_patch_series_hash: *const c_char,
    shmem_header_hash: *const c_char,
}

type QemuFaultCapabilitiesFn = extern "C" fn(*mut QemuFaultCapability, usize) -> usize;
type QemuFaultSubmitFn = extern "C" fn(*const QemuFaultCommand, *const u8, usize) -> c_int;
type QemuFaultCancelFn = extern "C" fn(u64) -> c_int;
type QemuFaultPeekFn = extern "C" fn(*mut QemuFaultResult, *mut usize) -> c_int;
type QemuFaultPollFn = extern "C" fn(*mut QemuFaultResult, *mut u8, usize, *mut usize) -> c_int;
type QemuFaultEventPeekFn = extern "C" fn(*mut QemuFaultEvent, *mut usize) -> c_int;
type QemuFaultEventEnvelopeVersionFn = extern "C" fn() -> c_int;
type QemuFaultEventPollFn = extern "C" fn(*mut QemuFaultEvent, *mut u8, usize, *mut usize) -> c_int;
type QemuFaultRegisterManifestFn =
    extern "C" fn(*mut QemuFaultRegisterCapability, usize, *mut u16, *mut *const c_char) -> usize;
type QemuFaultRegisterBindFn = extern "C" fn(*const u8, u32) -> c_int;
type QemuFaultRegisterBindArchitectureFn = extern "C" fn(*const u8) -> c_int;
type QemuFaultRegisterBindingsSealFn = extern "C" fn() -> c_int;
type QemuFaultInstructionManifestFn = extern "C" fn(*mut u8, usize, *mut u8, *mut u16) -> usize;
type QemuFaultInterruptManifestFn =
    extern "C" fn(*mut QemuFaultInterruptCapability, usize, *mut u16) -> usize;
type QemuFaultInterruptBindFn = extern "C" fn(u32, *const u8, *const u8, *const u8) -> c_int;
type QemuFaultInterruptBindingsSealFn = extern "C" fn() -> c_int;
type QemuFaultHardwareErrorManifestFn =
    extern "C" fn(*mut QemuFaultHardwareErrorCapability, usize, *mut u16) -> usize;
type QemuFaultHardwareErrorBindFn =
    extern "C" fn(u32, *const u8, *const u8, *const u8, *const u8, *const u8, *const u8) -> c_int;
type QemuFaultHardwareErrorBindingsSealFn = extern "C" fn(*const u8) -> c_int;
type QemuFaultClockManifestFn =
    extern "C" fn(*mut QemuFaultClockCapability, usize, *mut u16) -> usize;
type QemuFaultClockBindFn = extern "C" fn(u32, *const u8) -> c_int;
type QemuFaultClockBindingsSealFn = extern "C" fn(*const u8) -> c_int;
type QemuFaultAcceleratorManifestFn =
    extern "C" fn(*mut QemuFaultAcceleratorCapability, usize) -> usize;
type QemuFaultSystemManifestFn = extern "C" fn(*mut QemuFaultSystemManifest) -> c_int;

/// Resolved, closed QEMU fault registry operations.
#[derive(Clone, Copy)]
pub(crate) struct QemuFaultCommandApis {
    capabilities: QemuFaultCapabilitiesFn,
    submit: QemuFaultSubmitFn,
    // crucible-lint: allow rust-allow -- cancellation is retained for exact restore rollback wiring.
    #[allow(dead_code, reason = "cancellation is used by restore rollback wiring")]
    cancel: QemuFaultCancelFn,
    peek: QemuFaultPeekFn,
    poll: QemuFaultPollFn,
    event_peek: QemuFaultEventPeekFn,
    event_envelope_version: QemuFaultEventEnvelopeVersionFn,
    event_poll: QemuFaultEventPollFn,
    register_manifest: QemuFaultRegisterManifestFn,
    register_bind: QemuFaultRegisterBindFn,
    register_bind_architecture: QemuFaultRegisterBindArchitectureFn,
    register_bindings_seal: QemuFaultRegisterBindingsSealFn,
    instruction_manifest: QemuFaultInstructionManifestFn,
    interrupt_manifest: QemuFaultInterruptManifestFn,
    interrupt_bind: QemuFaultInterruptBindFn,
    interrupt_bindings_seal: QemuFaultInterruptBindingsSealFn,
    hardware_error_manifest: QemuFaultHardwareErrorManifestFn,
    hardware_error_bind: QemuFaultHardwareErrorBindFn,
    hardware_error_bindings_seal: QemuFaultHardwareErrorBindingsSealFn,
    clock_manifest: QemuFaultClockManifestFn,
    clock_bind: QemuFaultClockBindFn,
    clock_bindings_seal: QemuFaultClockBindingsSealFn,
    accelerator_manifest: QemuFaultAcceleratorManifestFn,
    system_manifest: QemuFaultSystemManifestFn,
}

impl QemuFaultCommandApis {
    /// Resolves every required fault-registry symbol from the loaded QEMU.
    #[cfg(unix)]
    pub(crate) fn resolve() -> Result<Self, FaultCommandBridgeError> {
        Ok(Self {
            capabilities: resolve_symbol(
                CAPABILITIES_SYMBOL_C,
                QEMU_PLUGIN_CRUCIBLE_FAULT_CAPABILITIES_SYMBOL,
            )?,
            submit: resolve_symbol(SUBMIT_SYMBOL_C, QEMU_PLUGIN_CRUCIBLE_FAULT_SUBMIT_SYMBOL)?,
            cancel: resolve_symbol(CANCEL_SYMBOL_C, QEMU_PLUGIN_CRUCIBLE_FAULT_CANCEL_SYMBOL)?,
            peek: resolve_symbol(PEEK_SYMBOL_C, QEMU_PLUGIN_CRUCIBLE_FAULT_PEEK_SYMBOL)?,
            poll: resolve_symbol(POLL_SYMBOL_C, QEMU_PLUGIN_CRUCIBLE_FAULT_POLL_SYMBOL)?,
            event_peek: resolve_symbol(
                EVENT_PEEK_SYMBOL_C,
                QEMU_PLUGIN_CRUCIBLE_FAULT_EVENT_PEEK_SYMBOL,
            )?,
            event_envelope_version: resolve_symbol(
                EVENT_ENVELOPE_VERSION_SYMBOL_C,
                QEMU_PLUGIN_CRUCIBLE_FAULT_EVENT_ENVELOPE_VERSION_SYMBOL,
            )?,
            event_poll: resolve_symbol(
                EVENT_POLL_SYMBOL_C,
                QEMU_PLUGIN_CRUCIBLE_FAULT_EVENT_POLL_SYMBOL,
            )?,
            register_manifest: resolve_symbol(
                REGISTER_MANIFEST_SYMBOL_C,
                QEMU_PLUGIN_CRUCIBLE_FAULT_REGISTER_MANIFEST_SYMBOL,
            )?,
            register_bind: resolve_symbol(
                REGISTER_BIND_SYMBOL_C,
                QEMU_PLUGIN_CRUCIBLE_FAULT_REGISTER_BIND_SYMBOL,
            )?,
            register_bind_architecture: resolve_symbol(
                REGISTER_BIND_ARCHITECTURE_SYMBOL_C,
                QEMU_PLUGIN_CRUCIBLE_FAULT_REGISTER_BIND_ARCHITECTURE_SYMBOL,
            )?,
            register_bindings_seal: resolve_symbol(
                REGISTER_BINDINGS_SEAL_SYMBOL_C,
                QEMU_PLUGIN_CRUCIBLE_FAULT_REGISTER_BINDINGS_SEAL_SYMBOL,
            )?,
            instruction_manifest: resolve_symbol(
                INSTRUCTION_MANIFEST_SYMBOL_C,
                QEMU_PLUGIN_CRUCIBLE_FAULT_INSTRUCTION_MANIFEST_SYMBOL,
            )?,
            interrupt_manifest: resolve_symbol(
                INTERRUPT_MANIFEST_SYMBOL_C,
                QEMU_PLUGIN_CRUCIBLE_FAULT_INTERRUPT_MANIFEST_SYMBOL,
            )?,
            interrupt_bind: resolve_symbol(
                INTERRUPT_BIND_SYMBOL_C,
                QEMU_PLUGIN_CRUCIBLE_FAULT_INTERRUPT_BIND_SYMBOL,
            )?,
            interrupt_bindings_seal: resolve_symbol(
                INTERRUPT_BINDINGS_SEAL_SYMBOL_C,
                QEMU_PLUGIN_CRUCIBLE_FAULT_INTERRUPT_BINDINGS_SEAL_SYMBOL,
            )?,
            hardware_error_manifest: resolve_symbol(
                HARDWARE_ERROR_MANIFEST_SYMBOL_C,
                QEMU_PLUGIN_CRUCIBLE_FAULT_HARDWARE_ERROR_MANIFEST_SYMBOL,
            )?,
            hardware_error_bind: resolve_symbol(
                HARDWARE_ERROR_BIND_SYMBOL_C,
                QEMU_PLUGIN_CRUCIBLE_FAULT_HARDWARE_ERROR_BIND_SYMBOL,
            )?,
            hardware_error_bindings_seal: resolve_symbol(
                HARDWARE_ERROR_BINDINGS_SEAL_SYMBOL_C,
                QEMU_PLUGIN_CRUCIBLE_FAULT_HARDWARE_ERROR_BINDINGS_SEAL_SYMBOL,
            )?,
            clock_manifest: resolve_symbol(
                CLOCK_MANIFEST_SYMBOL_C,
                QEMU_PLUGIN_CRUCIBLE_FAULT_CLOCK_MANIFEST_SYMBOL,
            )?,
            clock_bind: resolve_symbol(
                CLOCK_BIND_SYMBOL_C,
                QEMU_PLUGIN_CRUCIBLE_FAULT_CLOCK_BIND_SYMBOL,
            )?,
            clock_bindings_seal: resolve_symbol(
                CLOCK_BINDINGS_SEAL_SYMBOL_C,
                QEMU_PLUGIN_CRUCIBLE_FAULT_CLOCK_BINDINGS_SEAL_SYMBOL,
            )?,
            accelerator_manifest: resolve_symbol(
                ACCELERATOR_MANIFEST_SYMBOL_C,
                QEMU_PLUGIN_CRUCIBLE_FAULT_ACCELERATOR_MANIFEST_SYMBOL,
            )?,
            system_manifest: resolve_symbol(
                SYSTEM_MANIFEST_SYMBOL_C,
                QEMU_PLUGIN_CRUCIBLE_FAULT_SYSTEM_MANIFEST_SYMBOL,
            )?,
        })
    }

    #[cfg(not(unix))]
    pub(crate) const fn resolve() -> Result<Self, FaultCommandBridgeError> {
        Err(FaultCommandBridgeError::CapabilityUnavailable {
            symbol: QEMU_PLUGIN_CRUCIBLE_FAULT_CAPABILITIES_SYMBOL,
        })
    }

    fn capability_rows(self) -> Result<Vec<FaultCapabilityRowV1>, FaultCommandBridgeError> {
        let required = (self.capabilities)(std::ptr::null_mut(), 0);
        if required == 0 || required > 4_096 {
            return Err(FaultCommandBridgeError::CapabilityCount { required });
        }
        let empty = QemuFaultCapability {
            command_kind: 0,
            scope: 0,
            semantic_version: 0,
            phase_mask: 0,
            maximum_payload_bytes: 0,
            maximum_pending_commands: 0,
            required_feature_bits: 0,
            name: std::ptr::null(),
            payload_schema: std::ptr::null(),
        };
        let mut raw = vec![empty; required];
        let observed = (self.capabilities)(raw.as_mut_ptr(), raw.len());
        if observed != required {
            return Err(FaultCommandBridgeError::CapabilityRegistryChanged {
                expected: required,
                observed,
            });
        }
        let rows = raw
            .into_iter()
            .map(capability_row)
            .collect::<Result<Vec<_>, _>>()?;
        fault_capability_manifest_digest(&rows).map_err(|source| {
            let keys = rows
                .iter()
                .map(|row| {
                    format!(
                        "{}:{}:{}",
                        row.command_kind as u16, row.semantic_version, row.scope as u16
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            FaultCommandBridgeError::CapabilityRegistryAbi { keys, source }
        })?;
        Ok(rows)
    }

    fn register_manifest(
        self,
    ) -> Result<FaultRegisterCapabilityManifestV1, FaultCommandBridgeError> {
        let mut architecture = 0_u16;
        let mut cpu_model = std::ptr::null();
        let required =
            (self.register_manifest)(std::ptr::null_mut(), 0, &mut architecture, &mut cpu_model);
        if required == 0 || required > crucible_shmem::HARD_FAULT_TARGET_MANIFEST_ROWS {
            return Err(FaultCommandBridgeError::RegisterManifestCount { required });
        }
        let empty = QemuFaultRegisterCapability {
            numeric_id: 0,
            width_bits: 0,
            group: 0,
            reserved: 0,
            model_phase_mask: 0,
            side_effects: 0,
            capabilities: 0,
            name: std::ptr::null(),
            writable_mask: std::ptr::null(),
            reserved_mask: std::ptr::null(),
            ignored_mask: std::ptr::null(),
            read_only_mask: std::ptr::null(),
            mask_bytes: 0,
        };
        let mut raw = vec![empty; required];
        let observed = (self.register_manifest)(
            raw.as_mut_ptr(),
            raw.len(),
            &mut architecture,
            &mut cpu_model,
        );
        if observed != required {
            return Err(FaultCommandBridgeError::RegisterManifestChanged {
                expected: required,
                observed,
            });
        }
        let manifest = FaultRegisterCapabilityManifestV1 {
            architecture: FaultCapabilityScope::from_u16(architecture)
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
            cpu_model: capability_text(cpu_model, "cpu_model")?.to_owned(),
            rows: raw
                .into_iter()
                .map(register_capability_row)
                .collect::<Result<Vec<_>, _>>()?,
        };
        let encoded = manifest.encode().map_err(|source| {
            let keys = manifest
                .rows
                .iter()
                .map(|row| format!("{}:{}", row.numeric_id, row.name))
                .collect::<Vec<_>>()
                .join(",");
            FaultCommandBridgeError::RegisterManifestAbi {
                architecture,
                cpu_model: manifest.cpu_model.clone(),
                keys,
                source,
            }
        })?;
        FaultRegisterCapabilityManifestV1::decode(&encoded)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })
    }

    fn instruction_manifest(self) -> Result<InstructionEvidenceIdentity, FaultCommandBridgeError> {
        let mut sha256 = [0_u8; 32];
        let mut architecture = 0_u16;
        let required = (self.instruction_manifest)(
            std::ptr::null_mut(),
            0,
            sha256.as_mut_ptr(),
            &mut architecture,
        );
        if required == 0 || required > 16_384 || sha256 == [0; 32] {
            return Err(FaultCommandBridgeError::InstructionManifestCount { required });
        }
        let mut manifest = vec![0_u8; required];
        let mut copied_sha256 = [0_u8; 32];
        let mut copied_architecture = 0_u16;
        let observed = (self.instruction_manifest)(
            manifest.as_mut_ptr(),
            manifest.len(),
            copied_sha256.as_mut_ptr(),
            &mut copied_architecture,
        );
        if observed != required
            || copied_sha256 != sha256
            || copied_architecture != architecture
            || sha2::Sha256::digest(&manifest).as_slice() != sha256
        {
            return Err(FaultCommandBridgeError::InstructionManifestChanged);
        }
        Ok(InstructionEvidenceIdentity {
            architecture: FaultCapabilityScope::from_u16(architecture)
                .map_err(|_source| FaultCommandBridgeError::InstructionManifestChanged)?,
            manifest_sha256: sha256,
        })
    }

    fn interrupt_manifest(
        self,
    ) -> Result<FaultInterruptCapabilityManifestV1, FaultCommandBridgeError> {
        let mut architecture = 0_u16;
        let required = (self.interrupt_manifest)(std::ptr::null_mut(), 0, &mut architecture);
        if required == 0 || required > crucible_shmem::HARD_FAULT_TARGET_MANIFEST_ROWS {
            return Err(FaultCommandBridgeError::InterruptManifestCount { required });
        }
        let empty = QemuFaultInterruptCapability {
            family: 0,
            trigger: 0,
            polarity: 0,
            delivery_drop: 0,
            vector_start: 0,
            vector_end: 0,
            replacement_vector_start: 0,
            replacement_vector_end: 0,
            priority: 0,
            vmstate: 0,
            reserved: 0,
            model_phase_mask: 0,
            id: std::ptr::null(),
            controller: std::ptr::null(),
            source: std::ptr::null(),
            controller_version: std::ptr::null(),
            target_vcpus: std::ptr::null(),
            target_vcpu_count: 0,
        };
        let mut raw = vec![empty; required];
        let observed = (self.interrupt_manifest)(raw.as_mut_ptr(), raw.len(), &mut architecture);
        if observed != required {
            return Err(FaultCommandBridgeError::InterruptManifestChanged {
                expected: required,
                observed,
            });
        }
        let manifest = FaultInterruptCapabilityManifestV1 {
            architecture: FaultCapabilityScope::from_u16(architecture)
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
            rows: raw
                .into_iter()
                .map(interrupt_capability_row)
                .collect::<Result<Vec<_>, _>>()?,
        };
        FaultInterruptCapabilityManifestV1::decode(
            &manifest
                .encode()
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        )
        .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })
    }

    fn bind_interrupt_manifest(
        self,
        manifest: &FaultInterruptCapabilityManifestV1,
    ) -> Result<(), FaultCommandBridgeError> {
        for (index, row) in manifest.rows.iter().enumerate() {
            let row_index = u32::try_from(index)
                .map_err(|_source| FaultCommandBridgeError::InterruptManifestRow)?;
            let id = crucible_shmem::fault_object_id_hash_v1(&row.id);
            let controller = crucible_shmem::fault_object_id_hash_v1(&row.controller);
            let source = crucible_shmem::fault_object_id_hash_v1(&row.source);
            let status =
                (self.interrupt_bind)(row_index, id.as_ptr(), controller.as_ptr(), source.as_ptr());
            if status != 0 {
                return Err(FaultCommandBridgeError::InterruptManifestBind { row_index, status });
            }
        }
        let status = (self.interrupt_bindings_seal)();
        if status != 0 {
            return Err(FaultCommandBridgeError::InterruptManifestBind {
                row_index: 0,
                status,
            });
        }
        Ok(())
    }

    fn hardware_error_manifest(
        self,
    ) -> Result<FaultHardwareErrorCapabilityManifestV1, FaultCommandBridgeError> {
        let mut architecture = 0_u16;
        let required = (self.hardware_error_manifest)(std::ptr::null_mut(), 0, &mut architecture);
        if required > crucible_shmem::HARD_FAULT_TARGET_MANIFEST_ROWS {
            return Err(FaultCommandBridgeError::HardwareErrorManifestCount { required });
        }
        let empty = QemuFaultHardwareErrorCapability {
            record_kind: 0,
            error_class: 0,
            mechanism: 0,
            visibility_mask: 0,
            bank_number: 0,
            bank_count: 0,
            vector: 0,
            reserved0: 0,
            status_required: 0,
            status_allowed: 0,
            syndrome_required: 0,
            syndrome_allowed: 0,
            model_phase_mask: 0,
            privilege_mask: 0,
            corrected: 0,
            maskable: 0,
            vmstate: 0,
            reserved1: 0,
            id: std::ptr::null(),
            bank: std::ptr::null(),
            channel: std::ptr::null(),
            rank: std::ptr::null(),
            firmware: std::ptr::null(),
            state: std::ptr::null(),
        };
        let mut raw = vec![empty; required];
        let observed =
            (self.hardware_error_manifest)(raw.as_mut_ptr(), raw.len(), &mut architecture);
        if observed != required {
            return Err(FaultCommandBridgeError::HardwareErrorManifestChanged {
                expected: required,
                observed,
            });
        }
        let manifest = FaultHardwareErrorCapabilityManifestV1 {
            architecture: FaultCapabilityScope::from_u16(architecture)
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
            rows: raw
                .into_iter()
                .map(hardware_error_capability_row)
                .collect::<Result<Vec<_>, _>>()?,
        };
        FaultHardwareErrorCapabilityManifestV1::decode(
            &manifest
                .encode()
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        )
        .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })
    }

    fn bind_hardware_error_manifest(
        self,
        manifest: &FaultHardwareErrorCapabilityManifestV1,
    ) -> Result<(), FaultCommandBridgeError> {
        let manifest_payload = manifest
            .encode()
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;
        let manifest_sha256: [u8; 32] = sha2::Sha256::digest(&manifest_payload).into();
        for (index, row) in manifest.rows.iter().enumerate() {
            let row_index = u32::try_from(index)
                .map_err(|_source| FaultCommandBridgeError::HardwareErrorManifestRow)?;
            let id = crucible_shmem::fault_object_id_hash_v1(&row.id);
            let bank = crucible_shmem::fault_object_id_hash_v1(&row.bank);
            let channel = crucible_shmem::fault_object_id_hash_v1(&row.channel);
            let rank = crucible_shmem::fault_object_id_hash_v1(&row.rank);
            let firmware = crucible_shmem::fault_object_id_hash_v1(&row.firmware);
            let state = crucible_shmem::fault_object_id_hash_v1(&row.state);
            let status = (self.hardware_error_bind)(
                row_index,
                id.as_ptr(),
                bank.as_ptr(),
                channel.as_ptr(),
                rank.as_ptr(),
                firmware.as_ptr(),
                state.as_ptr(),
            );
            if status != 0 {
                return Err(FaultCommandBridgeError::HardwareErrorManifestBind {
                    row_index,
                    status,
                });
            }
        }
        let status = (self.hardware_error_bindings_seal)(manifest_sha256.as_ptr());
        if status != 0 {
            return Err(FaultCommandBridgeError::HardwareErrorManifestBind {
                row_index: 0,
                status,
            });
        }
        Ok(())
    }

    fn clock_manifest(self) -> Result<FaultClockCapabilityManifestV1, FaultCommandBridgeError> {
        let mut architecture = 0_u16;
        let required = (self.clock_manifest)(std::ptr::null_mut(), 0, &mut architecture);
        if required == 0 || required > crucible_shmem::HARD_FAULT_TARGET_MANIFEST_ROWS {
            return Err(FaultCommandBridgeError::ClockManifestCount { required });
        }
        let empty = QemuFaultClockCapability {
            source_kind: 0,
            architecture: 0,
            base_domain: 0,
            timer_relationship: 0,
            width_bits: 0,
            flags: 0,
            frequency_numerator: 0,
            frequency_denominator: 0,
            model_phase_mask: 0,
            vmstate: 0,
            monotonicity: 0,
            reserved: [0; 6],
            id: std::ptr::null(),
            implementation: std::ptr::null(),
        };
        let mut raw = vec![empty; required];
        let observed = (self.clock_manifest)(raw.as_mut_ptr(), raw.len(), &mut architecture);
        if observed != required {
            return Err(FaultCommandBridgeError::ClockManifestChanged {
                expected: required,
                observed,
            });
        }
        let architecture = FaultCapabilityScope::from_u16(architecture)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;
        let manifest = FaultClockCapabilityManifestV1 {
            architecture,
            rows: raw
                .into_iter()
                .map(|row| clock_capability_row(row, architecture))
                .collect::<Result<Vec<_>, _>>()?,
        };
        FaultClockCapabilityManifestV1::decode(
            &manifest
                .encode()
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        )
        .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })
    }

    fn accelerator_manifest(
        self,
    ) -> Result<Option<FaultAcceleratorCapabilityManifestV1>, FaultCommandBridgeError> {
        let required = (self.accelerator_manifest)(std::ptr::null_mut(), 0);
        if required == 0 {
            return Ok(None);
        }
        if required > crucible_shmem::HARD_FAULT_TARGET_MANIFEST_ROWS {
            return Err(FaultCommandBridgeError::AcceleratorManifestCount { required });
        }
        let empty = QemuFaultAcceleratorCapability {
            class_mask: 0,
            fault_family_mask: 0,
            queue_start: 0,
            queue_end: 0,
            queue_depth: 0,
            maximum_input_bytes: 0,
            maximum_output_bytes: 0,
            device_memory_bytes: 0,
            ecc_mode_mask: 0,
            job_kind_count: 0,
            vmstate: 0,
            reserved: [0; 7],
            id: std::ptr::null(),
            implementation: std::ptr::null(),
        };
        let mut raw = vec![empty; required];
        let observed = (self.accelerator_manifest)(raw.as_mut_ptr(), raw.len());
        if observed != required {
            return Err(FaultCommandBridgeError::AcceleratorManifestChanged {
                expected: required,
                observed,
            });
        }
        let manifest = FaultAcceleratorCapabilityManifestV1 {
            rows: raw
                .into_iter()
                .map(|row| {
                    if row.reserved != [0; 7] {
                        return Err(FaultCommandBridgeError::AcceleratorManifestRow);
                    }
                    Ok(FaultAcceleratorCapabilityRowV1 {
                        id: capability_text(row.id, "accelerator.id")?.to_owned(),
                        implementation: capability_text(
                            row.implementation,
                            "accelerator.implementation",
                        )?
                        .to_owned(),
                        class_mask: row.class_mask,
                        fault_family_mask: row.fault_family_mask,
                        queue_start: row.queue_start,
                        queue_end: row.queue_end,
                        queue_depth: row.queue_depth,
                        maximum_input_bytes: row.maximum_input_bytes,
                        maximum_output_bytes: row.maximum_output_bytes,
                        device_memory_bytes: row.device_memory_bytes,
                        ecc_mode_mask: row.ecc_mode_mask,
                        job_kind_count: row.job_kind_count,
                        vmstate: row.vmstate == 1,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
        };
        let encoded = manifest
            .encode()
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;
        FaultAcceleratorCapabilityManifestV1::decode(&encoded)
            .map(Some)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })
    }

    fn system_manifest(self) -> Result<FaultSystemCapabilityManifestV1, FaultCommandBridgeError> {
        let mut raw = QemuFaultSystemManifest {
            semantic_version: 0,
            vmstate_format_version: 0,
            vmstate_section_count: 0,
            reserved: 0,
            vmstate_sections_sha256: [0; 32],
            system_capability: std::ptr::null(),
            vmstate_capability: std::ptr::null(),
            qemu_build_id: std::ptr::null(),
            qemu_patch_series_hash: std::ptr::null(),
            shmem_header_hash: std::ptr::null(),
        };
        let status = (self.system_manifest)(&mut raw);
        if status != 0
            || raw.reserved != 0
            || capability_text(raw.system_capability, "system_capability")?
                != "qemu.fault-system.complete.v1"
            || capability_text(raw.vmstate_capability, "vmstate_capability")?
                != "qemu.fault-vmstate.v1"
        {
            return Err(FaultCommandBridgeError::SystemManifest { status });
        }
        let qemu_build_id = capability_text(raw.qemu_build_id, "qemu_build_id")?;
        let qemu_patch_series_hash =
            capability_text(raw.qemu_patch_series_hash, "qemu_patch_series_hash")?;
        let shmem_header_hash = capability_text(raw.shmem_header_hash, "shmem_header_hash")?;
        let identity_matches = match (
            EXPECTED_QEMU_BUILD_ID,
            EXPECTED_QEMU_PATCH_SERIES_HASH,
            EXPECTED_SHMEM_HEADER_HASH,
        ) {
            (Some(build), Some(patches), Some(shmem)) => {
                build == qemu_build_id
                    && patches == qemu_patch_series_hash
                    && shmem == shmem_header_hash
            }
            _ => cfg!(test),
        };
        if !identity_matches {
            return Err(FaultCommandBridgeError::SystemIdentityMismatch);
        }
        let manifest = FaultSystemCapabilityManifestV1 {
            semantic_version: raw.semantic_version,
            vmstate_format_version: raw.vmstate_format_version,
            vmstate_section_count: raw.vmstate_section_count,
            vmstate_sections_sha256: raw.vmstate_sections_sha256,
            emulator_build_id: text_digest(qemu_build_id, "qemu_build_id")?,
            emulator_patch_series_hash: text_digest(
                qemu_patch_series_hash,
                "qemu_patch_series_hash",
            )?,
            shmem_header_hash: text_digest(shmem_header_hash, "shmem_header_hash")?,
        };
        FaultSystemCapabilityManifestV1::decode(
            &manifest
                .encode()
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        )
        .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })
    }

    fn bind_clock_manifest(
        self,
        manifest: &FaultClockCapabilityManifestV1,
    ) -> Result<(), FaultCommandBridgeError> {
        let payload = manifest
            .encode()
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;
        let manifest_sha256: [u8; 32] = sha2::Sha256::digest(&payload).into();

        for (index, row) in manifest.rows.iter().enumerate() {
            let row_index = u32::try_from(index)
                .map_err(|_source| FaultCommandBridgeError::ClockManifestRow)?;
            let id = crucible_shmem::fault_object_id_hash_v1(&row.id);
            let status = (self.clock_bind)(row_index, id.as_ptr());
            if status != 0 {
                return Err(FaultCommandBridgeError::ClockManifestBind { row_index, status });
            }
        }
        let status = (self.clock_bindings_seal)(manifest_sha256.as_ptr());
        if status != 0 {
            return Err(FaultCommandBridgeError::ClockManifestBind {
                row_index: 0,
                status,
            });
        }
        Ok(())
    }

    fn bind_register_manifest(
        self,
        manifest: &FaultRegisterCapabilityManifestV1,
    ) -> Result<(), FaultCommandBridgeError> {
        let architecture_name = match manifest.architecture {
            FaultCapabilityScope::X86_64 => "x86_64",
            FaultCapabilityScope::Aarch64 => "aarch64",
            _ => return Err(FaultCommandBridgeError::RegisterManifestRow),
        };
        let architecture_identity = crucible_shmem::fault_object_id_hash_v1(architecture_name);
        let architecture_status = (self.register_bind_architecture)(architecture_identity.as_ptr());
        if architecture_status != 0 {
            return Err(FaultCommandBridgeError::RegisterManifestBind {
                numeric_id: 0,
                status: architecture_status,
            });
        }
        for row in &manifest.rows {
            let identity = crucible_shmem::fault_object_id_hash_v1(&row.name);
            let status = (self.register_bind)(identity.as_ptr(), row.numeric_id);
            if status != 0 {
                return Err(FaultCommandBridgeError::RegisterManifestBind {
                    numeric_id: row.numeric_id,
                    status,
                });
            }
        }
        let seal_status = (self.register_bindings_seal)();
        if seal_status != 0 {
            return Err(FaultCommandBridgeError::RegisterManifestBind {
                numeric_id: 0,
                status: seal_status,
            });
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) const fn test_stub() -> Self {
        Self {
            capabilities: test_capabilities,
            submit: test_submit,
            cancel: test_cancel,
            peek: test_peek,
            poll: test_poll,
            event_peek: test_event_peek,
            event_envelope_version: test_event_envelope_version,
            event_poll: test_event_poll,
            register_manifest: test_register_manifest,
            register_bind: test_register_bind,
            register_bind_architecture: test_register_bind_architecture,
            register_bindings_seal: test_register_bindings_seal,
            instruction_manifest: test_instruction_manifest,
            interrupt_manifest: test_interrupt_manifest,
            interrupt_bind: test_interrupt_bind,
            interrupt_bindings_seal: test_interrupt_bindings_seal,
            hardware_error_manifest: test_hardware_error_manifest,
            hardware_error_bind: test_hardware_error_bind,
            hardware_error_bindings_seal: test_hardware_error_bindings_seal,
            clock_manifest: test_clock_manifest,
            clock_bind: test_clock_bind,
            clock_bindings_seal: test_clock_bindings_seal,
            accelerator_manifest: test_accelerator_manifest,
            system_manifest: test_system_manifest,
        }
    }
}

#[cfg(test)]
extern "C" fn test_system_manifest(_out: *mut QemuFaultSystemManifest) -> c_int {
    static CAPABILITY: &[u8] = b"qemu.fault-system.complete.v1\0";
    static VMSTATE: &[u8] = b"qemu.fault-vmstate.v1\0";
    static BUILD_ID: std::sync::OnceLock<std::ffi::CString> = std::sync::OnceLock::new();
    static PATCH_SERIES_HASH: std::sync::OnceLock<std::ffi::CString> = std::sync::OnceLock::new();
    static SHMEM_HEADER_HASH: std::sync::OnceLock<std::ffi::CString> = std::sync::OnceLock::new();
    if _out.is_null() {
        return -libc::EINVAL;
    }
    let build_id = test_system_identity(&BUILD_ID, EXPECTED_QEMU_BUILD_ID);
    let patch_series_hash =
        test_system_identity(&PATCH_SERIES_HASH, EXPECTED_QEMU_PATCH_SERIES_HASH);
    let shmem_header_hash = test_system_identity(&SHMEM_HEADER_HASH, EXPECTED_SHMEM_HEADER_HASH);
    // SAFETY: the test caller provides one writable row and all referenced
    // strings have process-lifetime NUL-terminated storage.
    unsafe {
        *_out = QemuFaultSystemManifest {
            semantic_version: 1,
            vmstate_format_version: 1,
            vmstate_section_count: 9,
            reserved: 0,
            vmstate_sections_sha256: [1; 32],
            system_capability: CAPABILITY.as_ptr().cast(),
            vmstate_capability: VMSTATE.as_ptr().cast(),
            qemu_build_id: build_id.as_ptr(),
            qemu_patch_series_hash: patch_series_hash.as_ptr(),
            shmem_header_hash: shmem_header_hash.as_ptr(),
        };
    }
    0
}

#[cfg(test)]
fn test_system_identity(
    storage: &'static std::sync::OnceLock<std::ffi::CString>,
    packaged_identity: Option<&'static str>,
) -> &'static std::ffi::CStr {
    storage
        .get_or_init(|| {
            std::ffi::CString::new(
                packaged_identity
                    .unwrap_or("1111111111111111111111111111111111111111111111111111111111111111"),
            )
            .unwrap_or_else(|error| panic!("test system identity must be valid C text: {error}"))
        })
        .as_c_str()
}

#[cfg(test)]
extern "C" fn test_accelerator_manifest(
    _out: *mut QemuFaultAcceleratorCapability,
    _capacity: usize,
) -> usize {
    0
}

#[cfg(test)]
extern "C" fn test_instruction_manifest(
    _manifest: *mut u8,
    _capacity: usize,
    _sha256: *mut u8,
    _architecture: *mut u16,
) -> usize {
    0
}

#[cfg(test)]
extern "C" fn test_capabilities(out: *mut QemuFaultCapability, capacity: usize) -> usize {
    static NAME: &[u8] = b"boundary-probe\0";
    static SCHEMA: &[u8] = b"{}\0";
    if !out.is_null() && capacity >= 1 {
        // SAFETY: the caller advertises at least one element and QEMU's test
        // contract copies exactly one complete capability row synchronously.
        unsafe {
            *out = QemuFaultCapability {
                command_kind: FaultCommandKind::BoundaryProbe as u16,
                scope: 1,
                semantic_version: crucible_shmem::FAULT_COMMAND_SEMANTIC_VERSION,
                phase_mask: 0x7f,
                maximum_payload_bytes: 0,
                maximum_pending_commands: 8,
                required_feature_bits: 0,
                name: NAME.as_ptr().cast(),
                payload_schema: SCHEMA.as_ptr().cast(),
            };
        }
    }
    1
}

#[cfg(test)]
extern "C" fn test_submit(
    command: *const QemuFaultCommand,
    _payload: *const u8,
    _payload_len: usize,
) -> c_int {
    if command.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: the bridge passes one complete stack-owned command for the
    // duration of this synchronous ABI call.
    let command = unsafe { *command };
    if command.command_kind == FaultCommandKind::QueryCapabilities as u16 {
        TEST_CAPABILITY_RESULT_PENDING.with(|pending| pending.set(Some(command)));
    }
    0
}

#[cfg(test)]
extern "C" fn test_cancel(_command_sequence: u64) -> c_int {
    -libc::ENOENT
}

#[cfg(test)]
extern "C" fn test_peek(result: *mut QemuFaultResult, payload_length: *mut usize) -> c_int {
    if result.is_null() || payload_length.is_null() {
        return -libc::EINVAL;
    }
    TEST_CAPABILITY_RESULT_PENDING.with(|pending| {
        let Some(command) = pending.get() else {
            return 0;
        };
        // SAFETY: the bridge supplies complete writable output objects for
        // this synchronous, non-consuming ABI call.
        unsafe {
            *payload_length = 0;
            *result = test_result_for_command(command);
        }
        1
    })
}

#[cfg(test)]
extern "C" fn test_poll(
    result: *mut QemuFaultResult,
    _payload: *mut u8,
    _payload_capacity: usize,
    payload_length: *mut usize,
) -> c_int {
    if result.is_null() || payload_length.is_null() {
        return -libc::EINVAL;
    }
    TEST_CAPABILITY_RESULT_PENDING.with(|pending| {
        let Some(command) = pending.take() else {
            return 0;
        };
        // SAFETY: the bridge supplies one complete writable result object for
        // this synchronous ABI call.
        unsafe {
            *payload_length = 0;
            *result = test_result_for_command(command);
        }
        1
    })
}

#[cfg(test)]
extern "C" fn test_event_envelope_version() -> c_int {
    1
}

#[cfg(test)]
extern "C" fn test_event_poll(
    event: *mut QemuFaultEvent,
    _payload: *mut u8,
    _payload_capacity: usize,
    payload_length: *mut usize,
) -> c_int {
    if event.is_null() || payload_length.is_null() {
        return -libc::EINVAL;
    }
    0
}

#[cfg(test)]
extern "C" fn test_register_manifest(
    _out: *mut QemuFaultRegisterCapability,
    _capacity: usize,
    _architecture: *mut u16,
    _cpu_model: *mut *const c_char,
) -> usize {
    0
}

#[cfg(test)]
extern "C" fn test_interrupt_manifest(
    _out: *mut QemuFaultInterruptCapability,
    _capacity: usize,
    _architecture: *mut u16,
) -> usize {
    0
}

#[cfg(test)]
extern "C" fn test_interrupt_bind(
    _row_index: u32,
    _id: *const u8,
    _controller: *const u8,
    _source: *const u8,
) -> c_int {
    0
}

#[cfg(test)]
extern "C" fn test_interrupt_bindings_seal() -> c_int {
    0
}

#[cfg(test)]
extern "C" fn test_hardware_error_manifest(
    _out: *mut QemuFaultHardwareErrorCapability,
    _capacity: usize,
    _architecture: *mut u16,
) -> usize {
    0
}

#[cfg(test)]
extern "C" fn test_hardware_error_bind(
    _row_index: u32,
    _id: *const u8,
    _bank: *const u8,
    _channel: *const u8,
    _rank: *const u8,
    _firmware: *const u8,
    _state: *const u8,
) -> c_int {
    0
}

#[cfg(test)]
extern "C" fn test_hardware_error_bindings_seal(_manifest_sha256: *const u8) -> c_int {
    0
}

#[cfg(test)]
extern "C" fn test_clock_manifest(
    _out: *mut QemuFaultClockCapability,
    _capacity: usize,
    _architecture: *mut u16,
) -> usize {
    0
}

#[cfg(test)]
extern "C" fn test_clock_bind(_row_index: u32, _id: *const u8) -> c_int {
    0
}

#[cfg(test)]
extern "C" fn test_clock_bindings_seal(_manifest_sha256: *const u8) -> c_int {
    0
}

#[cfg(test)]
extern "C" fn test_register_bind(_identity: *const u8, _numeric_id: u32) -> c_int {
    0
}

#[cfg(test)]
extern "C" fn test_register_bind_architecture(_identity: *const u8) -> c_int {
    0
}

#[cfg(test)]
extern "C" fn test_register_bindings_seal() -> c_int {
    0
}

#[cfg(test)]
thread_local! {
    static TEST_CAPABILITY_RESULT_PENDING: std::cell::Cell<Option<QemuFaultCommand>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(unix)]
fn resolve_symbol<T: Copy>(
    symbol_name: &'static [u8],
    public_name: &'static str,
) -> Result<T, FaultCommandBridgeError> {
    // SAFETY: each name is a static NUL-terminated byte string. The closed
    // QEMU patch exports the exact function signature assigned at each call
    // site, and the returned pointer remains live for the QEMU process.
    let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, symbol_name.as_ptr().cast()) };
    if symbol.is_null() {
        return Err(FaultCommandBridgeError::CapabilityUnavailable {
            symbol: public_name,
        });
    }
    // SAFETY: the caller supplies the exact function-pointer type for the
    // corresponding closed symbol above; function and data pointers have the
    // same representation on supported QEMU hosts.
    Ok(unsafe { core::mem::transmute_copy::<*mut c_void, T>(&symbol) })
}

fn capability_row(
    raw: QemuFaultCapability,
) -> Result<FaultCapabilityRowV1, FaultCommandBridgeError> {
    let name = capability_text(raw.name, "name")?;
    let schema = capability_text(raw.payload_schema, "payload_schema")?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(CAPABILITY_HASH_DOMAIN);
    hasher.update(name.as_bytes());
    hasher.update(&[0]);
    hasher.update(schema.as_bytes());
    let row = FaultCapabilityRowV1 {
        command_kind: FaultCommandKind::from_u16(raw.command_kind)
            .map_err(|source| invalid_capability_row(raw, name, source))?,
        semantic_version: raw.semantic_version,
        scope: FaultCapabilityScope::from_u16(raw.scope)
            .map_err(|source| invalid_capability_row(raw, name, source))?,
        phase_mask: raw.phase_mask,
        maximum_payload_bytes: raw.maximum_payload_bytes,
        maximum_pending_commands: raw.maximum_pending_commands,
        required_feature_bits: raw.required_feature_bits,
        capability_hash: *hasher.finalize().as_bytes(),
    };
    FaultCapabilityRowV1::decode(&row.encode())
        .map_err(|source| invalid_capability_row(raw, name, source))
}

fn invalid_capability_row(
    raw: QemuFaultCapability,
    name: &str,
    source: FaultAbiError,
) -> FaultCommandBridgeError {
    FaultCommandBridgeError::CapabilityRowAbi {
        name: name.to_owned(),
        command_kind: raw.command_kind,
        scope: raw.scope,
        semantic_version: raw.semantic_version,
        phase_mask: raw.phase_mask,
        maximum_payload_bytes: raw.maximum_payload_bytes,
        maximum_pending_commands: raw.maximum_pending_commands,
        required_feature_bits: raw.required_feature_bits,
        source,
    }
}

fn register_capability_row(
    raw: QemuFaultRegisterCapability,
) -> Result<FaultRegisterCapabilityRowV1, FaultCommandBridgeError> {
    let expected_mask_bytes = usize::try_from(raw.width_bits.div_ceil(8))
        .map_err(|_source| FaultCommandBridgeError::RegisterManifestRow)?;
    if raw.reserved != 0
        || raw.width_bits == 0
        || raw.width_bits > crucible_shmem::HARD_FAULT_REGISTER_WIDTH_BITS
        || raw.mask_bytes != expected_mask_bytes
        || raw.writable_mask.is_null()
        || raw.reserved_mask.is_null()
        || raw.ignored_mask.is_null()
        || raw.read_only_mask.is_null()
    {
        return Err(FaultCommandBridgeError::RegisterManifestRow);
    }
    let copy_mask = |pointer: *const u8| {
        // SAFETY: the QEMU manifest export promises process-lifetime arrays of
        // exactly `ceil(width_bits / 8)` bytes. Width, the redundant length,
        // and null pointers were checked above before this synchronous copy.
        unsafe { std::slice::from_raw_parts(pointer, raw.mask_bytes) }.to_vec()
    };
    let row = FaultRegisterCapabilityRowV1 {
        numeric_id: raw.numeric_id,
        name: capability_text(raw.name, "register_name")?.to_owned(),
        width_bits: raw.width_bits,
        group: FaultRegisterGroupV1::from_u16(raw.group)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        model_phase_mask: raw.model_phase_mask,
        side_effects: raw.side_effects,
        capabilities: raw.capabilities,
        writable_mask: copy_mask(raw.writable_mask),
        reserved_mask: copy_mask(raw.reserved_mask),
        ignored_mask: copy_mask(raw.ignored_mask),
        read_only_mask: copy_mask(raw.read_only_mask),
    };
    row.validate()
        .map_err(|source| FaultCommandBridgeError::RegisterManifestRowAbi {
            numeric_id: raw.numeric_id,
            name: row.name.clone(),
            width_bits: raw.width_bits,
            group: raw.group,
            model_phase_mask: raw.model_phase_mask,
            side_effects: raw.side_effects,
            capabilities: raw.capabilities,
            mask_bytes: raw.mask_bytes,
            source,
        })?;
    Ok(row)
}

fn interrupt_capability_row(
    raw: QemuFaultInterruptCapability,
) -> Result<FaultInterruptCapabilityRowV1, FaultCommandBridgeError> {
    if raw.reserved != 0
        || raw.target_vcpu_count == 0
        || raw.target_vcpu_count > crucible_shmem::HARD_FAULT_TARGET_MANIFEST_ROWS
        || raw.target_vcpus.is_null()
    {
        return Err(FaultCommandBridgeError::InterruptManifestRow);
    }
    let target_vcpus =
        // SAFETY: the sealed QEMU manifest owns a process-lifetime target array;
        // its non-null pointer and hard-bounded element count were checked above.
        unsafe { std::slice::from_raw_parts(raw.target_vcpus, raw.target_vcpu_count) }.to_vec();
    Ok(FaultInterruptCapabilityRowV1 {
        id: capability_text(raw.id, "interrupt_id")?.to_owned(),
        controller: capability_text(raw.controller, "interrupt_controller")?.to_owned(),
        source: capability_text(raw.source, "interrupt_source")?.to_owned(),
        controller_version: capability_text(raw.controller_version, "controller_version")?
            .to_owned(),
        family: FaultInterruptFamilyV1::from_u16(raw.family)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        vector_start: raw.vector_start,
        vector_end: raw.vector_end,
        replacement_vector_start: raw.replacement_vector_start,
        replacement_vector_end: raw.replacement_vector_end,
        trigger: FaultInterruptTriggerV1::from_u16(raw.trigger)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        polarity: FaultInterruptPolarityV1::from_u16(raw.polarity)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        target_vcpus,
        model_phase_mask: raw.model_phase_mask,
        priority: raw.priority,
        delivery_drop: FaultInterruptDeliveryDropV1::from_u16(raw.delivery_drop)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        vmstate: raw.vmstate == 1,
    })
}

fn clock_capability_row(
    raw: QemuFaultClockCapability,
    architecture: FaultCapabilityScope,
) -> Result<FaultClockCapabilityRowV1, FaultCommandBridgeError> {
    if raw.architecture != architecture as u16 || raw.reserved != [0; 6] || raw.vmstate > 1 {
        return Err(FaultCommandBridgeError::ClockManifestRow);
    }
    Ok(FaultClockCapabilityRowV1 {
        id: capability_text(raw.id, "clock_id")?.to_owned(),
        implementation: capability_text(raw.implementation, "clock_implementation")?.to_owned(),
        source_kind: raw.source_kind,
        base_domain: raw.base_domain,
        timer_relationship: raw.timer_relationship,
        width_bits: raw.width_bits,
        flags: raw.flags,
        frequency_numerator: raw.frequency_numerator,
        frequency_denominator: raw.frequency_denominator,
        model_phase_mask: raw.model_phase_mask,
        vmstate: raw.vmstate == 1,
        monotonicity: raw.monotonicity,
    })
}

fn hardware_error_capability_row(
    raw: QemuFaultHardwareErrorCapability,
) -> Result<FaultHardwareErrorCapabilityRowV1, FaultCommandBridgeError> {
    if raw.reserved0 != 0
        || raw.reserved1 != 0
        || raw.corrected > 1
        || raw.maskable > 1
        || raw.vmstate > 1
    {
        return Err(FaultCommandBridgeError::HardwareErrorManifestRow);
    }
    Ok(FaultHardwareErrorCapabilityRowV1 {
        id: capability_text(raw.id, "hardware_error_id")?.to_owned(),
        bank: capability_text(raw.bank, "hardware_error_bank")?.to_owned(),
        channel: capability_text(raw.channel, "hardware_error_channel")?.to_owned(),
        rank: capability_text(raw.rank, "hardware_error_rank")?.to_owned(),
        firmware: capability_text(raw.firmware, "hardware_error_firmware")?.to_owned(),
        state: capability_text(raw.state, "hardware_error_state")?.to_owned(),
        record_kind: FaultHardwareErrorRecordKindV1::from_u16(raw.record_kind)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        error_class: FaultHardwareErrorClassV1::from_u16(raw.error_class)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        mechanism: FaultHardwareErrorMechanismV1::from_u16(raw.mechanism)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        visibility_mask: raw.visibility_mask,
        bank_number: raw.bank_number,
        bank_count: raw.bank_count,
        vector: raw.vector,
        status_required: raw.status_required,
        status_allowed: raw.status_allowed,
        syndrome_required: raw.syndrome_required,
        syndrome_allowed: raw.syndrome_allowed,
        model_phase_mask: raw.model_phase_mask,
        privilege_mask: raw.privilege_mask,
        corrected: raw.corrected == 1,
        maskable: raw.maskable == 1,
        vmstate: raw.vmstate == 1,
    })
}

fn capability_text(
    pointer: *const c_char,
    field: &'static str,
) -> Result<&'static str, FaultCommandBridgeError> {
    let pointer = NonNull::new(pointer.cast_mut())
        .ok_or(FaultCommandBridgeError::CapabilityStringNull { field })?;
    // SAFETY: QEMU's capability ABI promises process-lifetime NUL-terminated
    // strings, and the registry is sealed before this synchronous copy.
    unsafe { CStr::from_ptr(pointer.as_ptr()) }
        .to_str()
        .map_err(|_source| FaultCommandBridgeError::CapabilityStringUtf8 { field })
}

fn text_digest(text: &str, field: &'static str) -> Result<[u8; 32], FaultCommandBridgeError> {
    let bytes =
        hex::decode(text).map_err(|_source| FaultCommandBridgeError::CapabilityDigest { field })?;
    bytes
        .try_into()
        .map_err(|_source| FaultCommandBridgeError::CapabilityDigest { field })
}

fn command_kind(value: u16) -> Result<FaultCommandKind, FaultCommandBridgeError> {
    FaultCommandKind::from_u16(value)
        .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })
}

struct StableFaultCommandTransport {
    ring: NonNull<RingHeader>,
    slots: NonNull<FaultCommandSlotV1>,
    slot_count: usize,
    arena_header: NonNull<FaultPayloadArenaHeader>,
    arena: NonNull<u8>,
    arena_len: usize,
    arena_region_offset: u64,
}

struct StableFaultResultTransport {
    ring: NonNull<RingHeader>,
    slots: NonNull<FaultResultSlotV1>,
    slot_count: usize,
    arena_header: NonNull<FaultPayloadArenaHeader>,
    arena: NonNull<u8>,
    arena_len: usize,
    arena_region_offset: u64,
}

struct StableFaultEventTransport {
    ring: NonNull<RingHeader>,
    slots: NonNull<FaultEventSlotV1>,
    slot_count: usize,
    arena_header: NonNull<FaultPayloadArenaHeader>,
    arena: NonNull<u8>,
    arena_len: usize,
    arena_region_offset: u64,
}

#[derive(Clone)]
struct RegisterEvidenceIdentity {
    architecture: FaultCapabilityScope,
    manifest_digest: [u8; 32],
    cpu_model_digest: [u8; 32],
    rows: Vec<FaultRegisterCapabilityRowV1>,
}

#[derive(Clone)]
struct InstructionEvidenceIdentity {
    architecture: FaultCapabilityScope,
    manifest_sha256: [u8; 32],
}

#[derive(Clone)]
struct InstructionCommandExpectation {
    operation: NodeFaultOperationV1,
    binding_hash: [u8; 32],
    generation: u64,
    action_hash: [u8; 32],
    target_hash: [u8; 32],
    vcpu_index: u32,
    model_phase: u16,
    pc_start: u64,
    pc_length: u64,
    instruction_bytes: Option<Vec<u8>>,
    opcode_class: Option<u32>,
    input_state_sha256: Option<[u8; 32]>,
    mutation_kind: FaultInstructionMutationKindV1,
    replay_total: u32,
    next_replay_ordinal: u32,
    register_mutation: Option<RegisterMutationExpectation>,
}

#[derive(Clone)]
struct ExceptionCommandExpectation {
    binding_hash: [u8; 32],
    generation: u64,
    action_hash: [u8; 32],
    target_hash: [u8; 32],
    architecture: FaultCapabilityScope,
    model_phase: u16,
    vcpu_index: u32,
    vector: u32,
    syndrome: u64,
    fault_address: Option<u64>,
    before_instruction: bool,
    maskable: bool,
    hardware_record: Option<HardwareExceptionExpectation>,
}

#[derive(Clone)]
enum HardwareExceptionExpectation {
    X86MachineCheck {
        bank: u32,
        status: u64,
        global_status: u64,
        address: Option<u64>,
        misc: Option<u64>,
        corrected: bool,
    },
    Aarch64Ras {
        esr: u64,
        far: Option<u64>,
        disr: Option<u64>,
        asynchronous: bool,
        corrected: bool,
        fatal: bool,
    },
}

#[derive(Clone)]
struct MemoryEccCommandExpectation {
    binding_hash: [u8; 32],
    generation: u64,
    action_hash: [u8; 32],
    target_hash: [u8; 32],
    model_phase: u16,
    target_vcpu: u32,
    kind: u32,
    address: u64,
    syndrome: u64,
    bank: [u8; 32],
    channel: [u8; 32],
    rank: [u8; 32],
    visibility: serde_json::Value,
}

#[derive(Clone)]
struct ClockCommandExpectation {
    operation: NodeFaultOperationV1,
    command_kind: u16,
    binding_hash: [u8; 32],
    model_phase: u16,
    source_ids: Vec<[u8; 32]>,
    parameters: ClockCommandParameters,
}

#[derive(Clone)]
struct AcceleratorCommandExpectation {
    operation: NodeFaultOperationV1,
    command_kind: u16,
    binding_hash: [u8; 32],
    generation: u64,
    action_hash: [u8; 32],
    target_hash: [u8; 32],
    model_phase: u16,
    fields: BTreeMap<u16, Vec<u8>>,
}

#[derive(Clone)]
enum ClockCommandParameters {
    Remove,
    Transform {
        kind: u32,
        signed_value: i64,
        ratio: [u64; 2],
        unsigned_value: u64,
        process: Option<serde_json::Value>,
        monotonicity: u32,
        overdue_policy: u32,
    },
    SourceState {
        transition: serde_json::Value,
        synchronization: serde_json::Value,
    },
}

#[derive(Clone)]
struct RegisterMutationExpectation {
    vcpu_index: u32,
    numeric_id: u32,
    model_phase: u16,
    mutation_kind: FaultRegisterMutationKindV1,
    first_bit: u32,
    bit_count: u32,
    mask: Vec<u8>,
    value: Vec<u8>,
}

#[derive(Clone)]
struct RegisterCommandExpectation {
    operation: NodeFaultOperationV1,
    binding_hash: [u8; 32],
    mutation: Option<RegisterMutationExpectation>,
}

impl StableFaultCommandTransport {
    fn new(view: MappedFaultCommandTransportMut<'_>) -> Result<Self, FaultCommandBridgeError> {
        Ok(Self {
            ring: NonNull::from(view.ring),
            slots: NonNull::new(view.slots.as_mut_ptr()).ok_or(
                FaultCommandBridgeError::EmptyTransport {
                    direction: "command",
                },
            )?,
            slot_count: view.slots.len(),
            arena_header: NonNull::from(view.arena_header),
            arena: NonNull::new(view.arena.as_mut_ptr()).ok_or(
                FaultCommandBridgeError::EmptyTransport {
                    direction: "command",
                },
            )?,
            arena_len: view.arena.len(),
            arena_region_offset: view.arena_region_offset,
        })
    }

    fn dequeue(&self) -> Result<Option<DequeuedFaultCommand>, FaultCommandBridgeError> {
        // SAFETY: the setup mapping owns every validated address for the bridge
        // lifetime. This bridge is the sole plugin consumer for this VM's SPSC
        // command ring and only reads slot/arena bytes published by the host.
        let (ring, slots, arena_header, arena) = unsafe {
            (
                self.ring.as_ref(),
                core::slice::from_raw_parts(self.slots.as_ptr(), self.slot_count),
                self.arena_header.as_ref(),
                core::slice::from_raw_parts(self.arena.as_ptr(), self.arena_len),
            )
        };
        dequeue_fault_command(ring, slots, arena_header, arena, self.arena_region_offset)
            .map_err(|source| FaultCommandBridgeError::Transport { source })
    }
}

impl StableFaultResultTransport {
    fn new(view: MappedFaultResultTransportMut<'_>) -> Result<Self, FaultCommandBridgeError> {
        Ok(Self {
            ring: NonNull::from(view.ring),
            slots: NonNull::new(view.slots.as_mut_ptr()).ok_or(
                FaultCommandBridgeError::EmptyTransport {
                    direction: "result",
                },
            )?,
            slot_count: view.slots.len(),
            arena_header: NonNull::from(view.arena_header),
            arena: NonNull::new(view.arena.as_mut_ptr()).ok_or(
                FaultCommandBridgeError::EmptyTransport {
                    direction: "result",
                },
            )?,
            arena_len: view.arena.len(),
            arena_region_offset: view.arena_region_offset,
        })
    }

    fn enqueue(
        &mut self,
        header: FaultResultHeaderV1,
        payload: &[u8],
    ) -> Result<(), FaultCommandBridgeError> {
        // SAFETY: the setup mapping retains these validated addresses. The live
        // callback mutex makes this bridge the sole result producer, while the
        // host touches only the published SPSC read side.
        let (ring, slots, arena_header, arena) = unsafe {
            (
                self.ring.as_ref(),
                core::slice::from_raw_parts_mut(self.slots.as_ptr(), self.slot_count),
                self.arena_header.as_ref(),
                core::slice::from_raw_parts_mut(self.arena.as_ptr(), self.arena_len),
            )
        };
        enqueue_fault_result(
            ring,
            slots,
            arena_header,
            arena,
            self.arena_region_offset,
            header,
            payload,
        )
        .map_err(|source| FaultCommandBridgeError::Transport { source })
    }

    fn can_enqueue(&self, payload_len: usize) -> Result<bool, FaultCommandBridgeError> {
        // SAFETY: the validated setup mapping owns these addresses and the
        // callback mutex serializes this producer's preflight and enqueue.
        let (ring, slots, arena_header, arena) = unsafe {
            (
                self.ring.as_ref(),
                core::slice::from_raw_parts(self.slots.as_ptr(), self.slot_count),
                self.arena_header.as_ref(),
                core::slice::from_raw_parts(self.arena.as_ptr(), self.arena_len),
            )
        };
        can_enqueue_fault_result(ring, slots, arena_header, arena, payload_len)
            .map_err(|source| FaultCommandBridgeError::Transport { source })
    }
}

impl StableFaultEventTransport {
    fn new(view: MappedFaultEventTransportMut<'_>) -> Result<Self, FaultCommandBridgeError> {
        Ok(Self {
            ring: NonNull::from(view.ring),
            slots: NonNull::new(view.slots.as_mut_ptr())
                .ok_or(FaultCommandBridgeError::EmptyTransport { direction: "event" })?,
            slot_count: view.slots.len(),
            arena_header: NonNull::from(view.arena_header),
            arena: NonNull::new(view.arena.as_mut_ptr())
                .ok_or(FaultCommandBridgeError::EmptyTransport { direction: "event" })?,
            arena_len: view.arena.len(),
            arena_region_offset: view.arena_region_offset,
        })
    }

    fn can_enqueue(&self, payload_len: usize) -> Result<bool, FaultCommandBridgeError> {
        // SAFETY: the validated setup mapping owns these addresses and the
        // callback mutex serializes this producer's preflight and enqueue.
        let (ring, slots, arena_header, arena) = unsafe {
            (
                self.ring.as_ref(),
                core::slice::from_raw_parts(self.slots.as_ptr(), self.slot_count),
                self.arena_header.as_ref(),
                core::slice::from_raw_parts(self.arena.as_ptr(), self.arena_len),
            )
        };
        can_enqueue_fault_event(ring, slots, arena_header, arena, payload_len)
            .map_err(|source| FaultCommandBridgeError::Transport { source })
    }

    fn enqueue(
        &mut self,
        header: FaultEventHeaderV1,
        payload: &[u8],
    ) -> Result<(), FaultCommandBridgeError> {
        // SAFETY: the setup mapping retains these validated addresses. The
        // callback mutex makes this bridge the sole event producer, while the
        // host touches only the published SPSC read side.
        let (ring, slots, arena_header, arena) = unsafe {
            (
                self.ring.as_ref(),
                core::slice::from_raw_parts_mut(self.slots.as_ptr(), self.slot_count),
                self.arena_header.as_ref(),
                core::slice::from_raw_parts_mut(self.arena.as_ptr(), self.arena_len),
            )
        };
        enqueue_fault_event(
            ring,
            slots,
            arena_header,
            arena,
            self.arena_region_offset,
            header,
            payload,
        )
        .map_err(|source| FaultCommandBridgeError::Transport { source })
    }
}

/// Live bridge for one VM's bounded command, result, and event transports.
pub(crate) struct FaultCommandBridge {
    apis: QemuFaultCommandApis,
    target_node_hash: [u8; 32],
    commands: StableFaultCommandTransport,
    results: StableFaultResultTransport,
    events: StableFaultEventTransport,
    last_sequence: u64,
    capability_payload: Vec<u8>,
    capability_queries: BTreeSet<u64>,
    register_manifest_payload: Option<Vec<u8>>,
    interrupt_manifest_payload: Option<Vec<u8>>,
    hardware_error_manifest_payload: Option<Vec<u8>>,
    clock_manifest_payload: Option<Vec<u8>>,
    accelerator_manifest_payload: Option<Vec<u8>>,
    system_manifest_payload: Vec<u8>,
    register_evidence_identity: Option<RegisterEvidenceIdentity>,
    instruction_evidence_identity: Option<InstructionEvidenceIdentity>,
    register_commands: BTreeMap<u64, RegisterCommandExpectation>,
    active_register_bindings: BTreeMap<[u8; 32], u64>,
    instruction_commands: BTreeMap<u64, InstructionCommandExpectation>,
    active_instruction_bindings: BTreeMap<[u8; 32], u64>,
    exception_commands: BTreeMap<u64, ExceptionCommandExpectation>,
    memory_ecc_commands: BTreeMap<u64, MemoryEccCommandExpectation>,
    clock_commands: BTreeMap<u64, ClockCommandExpectation>,
    active_clock_bindings: BTreeMap<[u8; 32], u64>,
    accelerator_commands: BTreeMap<u64, AcceleratorCommandExpectation>,
    active_accelerator_bindings: BTreeMap<[u8; 32], u64>,
    prepared_commands: BTreeSet<u64>,
    prepare_only_commands: BTreeSet<u64>,
    pending_command: Option<DequeuedFaultCommand>,
    initialized: bool,
}

mod accelerator_evidence;
mod bridge;
mod clock_evidence;
mod event_envelope;
mod instruction_evidence;
mod lifecycle_evidence;
#[cfg(test)]
mod test_support;
use accelerator_evidence::*;
use clock_evidence::*;
use event_envelope::*;
use instruction_evidence::*;
use lifecycle_evidence::*;
#[cfg(test)]
use test_support::{TEST_EVENT_PENDING, test_event_peek, test_result_for_command};
/// Failure of the lossless fault command bridge.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FaultCommandBridgeError {
    /// A command pump ran before the first realized vCPU admitted manifests.
    #[error("QEMU fault bridge is not initialized by a realized vCPU")]
    NotInitialized,
    /// Bridge initialization failed while admitting one named capability set.
    #[error("QEMU fault bridge initialization failed at {stage}: {source}")]
    InitializationStage {
        /// Stable initialization stage name.
        stage: &'static str,
        /// Underlying typed admission failure.
        source: Box<FaultCommandBridgeError>,
    },
    /// A required patched-QEMU symbol is absent.
    #[error("required QEMU fault capability `{symbol}` is unavailable")]
    CapabilityUnavailable {
        /// Missing symbol.
        symbol: &'static str,
    },
    /// QEMU reported an unsupported private event-envelope schema.
    #[error("QEMU fault event envelope version {observed} is unsupported")]
    EventEnvelopeVersion {
        /// Version returned by the required QEMU runtime API.
        observed: c_int,
    },
    /// QEMU returned a malformed or identity-inconsistent event envelope.
    #[error("QEMU fault event envelope is invalid")]
    EventEnvelope,
    /// The registry reported an invalid row count.
    #[error("QEMU fault registry reported invalid capability count {required}")]
    CapabilityCount {
        /// Reported row count.
        required: usize,
    },
    /// The supposedly immutable registry changed between size and copy calls.
    #[error("QEMU fault registry changed from {expected} to {observed} rows")]
    CapabilityRegistryChanged {
        /// First size query.
        expected: usize,
        /// Copy-call result.
        observed: usize,
    },
    /// The architecture register registry reported an invalid row count.
    #[error("QEMU register manifest reported invalid row count {required}")]
    RegisterManifestCount {
        /// Reported row count.
        required: usize,
    },
    /// The immutable register registry changed between size and copy calls.
    #[error("QEMU register manifest changed from {expected} to {observed} rows")]
    RegisterManifestChanged {
        /// First size query.
        expected: usize,
        /// Copy-call result.
        observed: usize,
    },
    /// A raw register row contained invalid reserved, pointer, or mask state.
    #[error("QEMU register manifest row has invalid raw framing")]
    RegisterManifestRow,
    /// A framed register row violated the public semantic contract.
    #[error(
        "QEMU register manifest row `{name}` is invalid: id={numeric_id} width={width_bits} group={group} phases={model_phase_mask:#x} side_effects={side_effects:#x} capabilities={capabilities:#x} mask_bytes={mask_bytes}: {source}"
    )]
    RegisterManifestRowAbi {
        /// QEMU-private numeric register ID.
        numeric_id: u32,
        /// Stable public register name.
        name: String,
        /// Register width in bits.
        width_bits: u32,
        /// Raw register-group tag.
        group: u16,
        /// Raw supported model-phase mask.
        model_phase_mask: u64,
        /// Raw derived-state side-effect flags.
        side_effects: u32,
        /// Raw mutation and VMState flags.
        capabilities: u32,
        /// Redundant mask byte count returned by QEMU.
        mask_bytes: usize,
        /// Public ABI validation failure.
        source: FaultAbiError,
    },
    /// The assembled register manifest violated its global canonical contract.
    #[error(
        "QEMU register manifest is invalid: architecture={architecture} cpu_model=`{cpu_model}` rows=[{keys}]: {source}"
    )]
    RegisterManifestAbi {
        /// Raw architecture scope returned by QEMU.
        architecture: u16,
        /// Realized QEMU CPU model identity.
        cpu_model: String,
        /// Ordered numeric-ID and public-name keys.
        keys: String,
        /// Public ABI validation failure.
        source: FaultAbiError,
    },
    /// QEMU rejected a sealed public identity-to-register binding.
    #[error("QEMU rejected register binding for numeric ID {numeric_id}: status {status}")]
    RegisterManifestBind {
        /// Manifest numeric ID.
        numeric_id: u32,
        /// Negative errno-style status.
        status: c_int,
    },
    /// The architecture interrupt registry reported an invalid row count.
    #[error("QEMU interrupt manifest reported invalid row count {required}")]
    InterruptManifestCount {
        /// Reported row count.
        required: usize,
    },
    /// The immutable interrupt registry changed between size and copy calls.
    #[error("QEMU interrupt manifest changed from {expected} to {observed} rows")]
    InterruptManifestChanged {
        /// First size query.
        expected: usize,
        /// Copy-call result.
        observed: usize,
    },
    /// A raw interrupt row contained invalid reserved or pointer state.
    #[error("QEMU interrupt manifest row has invalid raw framing")]
    InterruptManifestRow,
    /// QEMU rejected one public interrupt identity binding.
    #[error("QEMU rejected interrupt binding for row {row_index}: status {status}")]
    InterruptManifestBind {
        /// Zero-based manifest row index.
        row_index: u32,
        /// Negative errno-style status.
        status: c_int,
    },
    /// The hardware-error registry reported an invalid row count.
    #[error("QEMU hardware-error manifest reported invalid row count {required}")]
    HardwareErrorManifestCount {
        /// Reported row count.
        required: usize,
    },
    /// The immutable hardware-error registry changed between size and copy calls.
    #[error("QEMU hardware-error manifest changed from {expected} to {observed} rows")]
    HardwareErrorManifestChanged {
        /// First size query.
        expected: usize,
        /// Copy-call result.
        observed: usize,
    },
    /// A raw hardware-error row contained invalid reserved or pointer state.
    #[error("QEMU hardware-error manifest row has invalid raw framing")]
    HardwareErrorManifestRow,
    /// QEMU returned malformed or manifest-inconsistent hardware-error evidence.
    #[error("QEMU hardware-error evidence is invalid")]
    HardwareErrorEvidence,
    /// QEMU returned malformed or manifest-inconsistent guest-clock evidence.
    #[error("QEMU guest-clock evidence is invalid")]
    ClockEvidence,
    /// QEMU returned accelerator evidence inconsistent with its admitted rule.
    #[error("QEMU accelerator evidence is invalid")]
    AcceleratorEvidence,
    /// QEMU rejected one public hardware-error identity binding.
    #[error("QEMU rejected hardware-error binding for row {row_index}: status {status}")]
    HardwareErrorManifestBind {
        /// Zero-based manifest row index.
        row_index: u32,
        /// Negative errno-style status.
        status: c_int,
    },
    /// The guest-clock registry reported an invalid row count.
    #[error("QEMU clock manifest reported invalid row count {required}")]
    ClockManifestCount {
        /// Reported row count.
        required: usize,
    },
    /// The immutable guest-clock registry changed between size and copy calls.
    #[error("QEMU clock manifest changed from {expected} to {observed} rows")]
    ClockManifestChanged {
        /// First size query.
        expected: usize,
        /// Copy-call result.
        observed: usize,
    },
    /// A raw guest-clock row contained invalid framing or identity state.
    #[error("QEMU clock manifest row has invalid raw framing")]
    ClockManifestRow,
    /// QEMU rejected one public guest-clock identity binding.
    #[error("QEMU rejected clock binding for row {row_index}: status {status}")]
    ClockManifestBind {
        /// Zero-based manifest row index.
        row_index: u32,
        /// Negative errno-style status.
        status: c_int,
    },
    /// The accelerator registry reported an invalid row count.
    #[error("QEMU accelerator manifest reported invalid row count {required}")]
    AcceleratorManifestCount {
        /// Reported row count.
        required: usize,
    },
    /// The immutable accelerator registry changed between size and copy calls.
    #[error("QEMU accelerator manifest changed from {expected} to {observed} rows")]
    AcceleratorManifestChanged {
        /// First size query.
        expected: usize,
        /// Copy-call result.
        observed: usize,
    },
    /// A raw accelerator row contained invalid framing or identity state.
    #[error("QEMU accelerator manifest row has invalid raw framing")]
    AcceleratorManifestRow,
    /// QEMU did not expose a complete realized fault-system identity.
    #[error("QEMU fault-system manifest is incomplete: status {status}")]
    SystemManifest {
        /// Negative errno-style status returned by QEMU.
        status: c_int,
    },
    /// The live QEMU identity differs from the one compiled into this plugin.
    #[error("live QEMU fault-system identity does not match the plugin build identity")]
    SystemIdentityMismatch,
    /// Register mutation was advertised without its required capability row.
    #[error("QEMU register manifest has no CPU register-transform capability")]
    RegisterCapabilityMissing,
    /// QEMU returned malformed or identity-inconsistent register evidence.
    #[error("QEMU register mutation evidence is invalid")]
    RegisterEvidence,
    /// The instruction manifest reported an invalid byte count.
    #[error("QEMU instruction manifest reported invalid byte count {required}")]
    InstructionManifestCount {
        /// Reported manifest byte count.
        required: usize,
    },
    /// The instruction manifest changed between identity and copy calls.
    #[error("QEMU instruction manifest changed during bridge initialization")]
    InstructionManifestChanged,
    /// QEMU returned malformed or command-inconsistent instruction evidence.
    #[error("QEMU instruction mutation evidence is invalid")]
    InstructionEvidence,
    /// QEMU returned malformed or command-inconsistent exception evidence.
    #[error("QEMU delivered-exception evidence is invalid")]
    ExceptionEvidence,
    /// A process-lifetime capability string pointer was null.
    #[error("QEMU fault capability field `{field}` is null")]
    CapabilityStringNull {
        /// Invalid field.
        field: &'static str,
    },
    /// A capability string was not valid UTF-8.
    #[error("QEMU fault capability field `{field}` is not UTF-8")]
    CapabilityStringUtf8 {
        /// Invalid field.
        field: &'static str,
    },
    /// A capability identity was not an exact lowercase SHA-256 digest.
    #[error("QEMU fault capability field `{field}` is not a 32-byte hex digest")]
    CapabilityDigest {
        /// Invalid field.
        field: &'static str,
    },
    /// A capability row violated the public ABI.
    #[error("QEMU fault capability ABI is invalid: {source}")]
    CapabilityAbi {
        /// Public ABI validation failure.
        source: FaultAbiError,
    },
    /// One QEMU registry row violated the public ABI contract.
    #[error(
        "QEMU fault capability row `{name}` is invalid: kind={command_kind} scope={scope} version={semantic_version} phase_mask={phase_mask:#x} max_payload={maximum_payload_bytes} max_pending={maximum_pending_commands} features={required_feature_bits:#x}: {source}"
    )]
    CapabilityRowAbi {
        /// Stable QEMU capability name.
        name: String,
        /// Raw command-kind tag.
        command_kind: u16,
        /// Raw capability-scope tag.
        scope: u16,
        /// Raw semantic version.
        semantic_version: u32,
        /// Raw supported-phase bit mask.
        phase_mask: u32,
        /// Raw maximum command payload bytes.
        maximum_payload_bytes: u32,
        /// Raw maximum pending command count.
        maximum_pending_commands: u32,
        /// Raw required feature bit mask.
        required_feature_bits: u64,
        /// Public ABI validation failure.
        source: FaultAbiError,
    },
    /// The complete QEMU registry was not in canonical key order.
    #[error("QEMU fault capability registry keys [{keys}] are invalid: {source}")]
    CapabilityRegistryAbi {
        /// Ordered `kind:version:scope` keys returned by QEMU.
        keys: String,
        /// Public ABI validation failure.
        source: FaultAbiError,
    },
    /// The configured node identity was the reserved all-zero value.
    #[error("fault target node hash must not be all zero")]
    ZeroTargetNodeHash,
    /// The setup mapping could not provide the VM's dedicated transport.
    #[error("mapped fault transport is unavailable: {source}")]
    MappedTransport {
        /// Typed mapping failure.
        source: MappedSetupRegionAccessError,
    },
    /// A validated mapped transport had no storage.
    #[error("mapped fault {direction} transport has no storage")]
    EmptyTransport {
        /// Transport direction.
        direction: &'static str,
    },
    /// Shared-memory transport framing or capacity failed.
    #[error("fault shared-memory transport failed: {source}")]
    Transport {
        /// Transport error.
        source: FaultTransportError,
    },
    /// A malformed command had no usable correlation sequence.
    #[error("malformed fault command has sequence zero and cannot receive a canonical result")]
    UncorrelatableMalformedCommand,
    /// The platform cannot address the protocol's hard payload bound.
    #[error("fault payload capacity does not fit this platform")]
    PayloadCapacity,
    /// QEMU could not preserve a submitted command result.
    #[error("QEMU fault submission failed with status {status}")]
    QemuSubmit {
        /// Negative errno-style status.
        status: c_int,
    },
    /// QEMU result polling failed.
    #[error("QEMU fault result poll failed with status {status}")]
    QemuPoll {
        /// Negative errno-style status.
        status: c_int,
    },
    /// QEMU result peeking failed without consuming the result.
    #[error("QEMU fault result peek failed with status {status}")]
    QemuPeek {
        /// Negative errno-style status.
        status: c_int,
    },
    /// The single-consumer result head changed between peek and poll.
    #[error(
        "QEMU fault result changed after peek: expected sequence {expected_sequence}, observed {observed_sequence}"
    )]
    QemuPeekChanged {
        /// Sequence observed non-destructively.
        expected_sequence: u64,
        /// Sequence returned by consuming poll.
        observed_sequence: u64,
    },
    /// QEMU changed the result payload length between peek and poll.
    #[error(
        "QEMU fault payload length changed after peek: expected {expected}, observed {observed}"
    )]
    QemuPayloadLengthChanged {
        /// Length observed non-destructively.
        expected: usize,
        /// Length returned by consuming poll.
        observed: usize,
    },
    /// QEMU claimed a result larger than the hard buffer.
    #[error("QEMU fault result payload length {length} exceeds buffer {capacity}")]
    QemuPayloadLength {
        /// Returned length.
        length: usize,
        /// Available bytes.
        capacity: usize,
    },
    /// QEMU event polling failed.
    #[error("QEMU fault event poll failed with status {status}")]
    QemuEventPoll {
        /// Negative errno-style status.
        status: c_int,
    },
    /// QEMU event peeking failed without consuming the event.
    #[error("QEMU fault event peek failed with status {status}")]
    QemuEventPeek {
        /// Negative errno-style status.
        status: c_int,
    },
    /// The single-consumer event head changed between peek and poll.
    #[error(
        "QEMU fault event changed after peek: expected sequence {expected_sequence}, observed {observed_sequence}"
    )]
    QemuEventPeekChanged {
        /// Sequence observed non-destructively.
        expected_sequence: u64,
        /// Sequence returned by consuming poll.
        observed_sequence: u64,
    },
    /// QEMU changed the event payload length between peek and poll.
    #[error(
        "QEMU fault event payload length changed after peek: expected {expected}, observed {observed}"
    )]
    QemuEventPayloadLengthChanged {
        /// Length observed non-destructively.
        expected: usize,
        /// Length returned by consuming poll.
        observed: usize,
    },
    /// QEMU claimed an empty or oversized event evidence payload.
    #[error("QEMU fault event payload length {length} is outside 1..={capacity}")]
    QemuEventPayloadLength {
        /// Returned length.
        length: usize,
        /// Maximum available bytes.
        capacity: usize,
    },
    /// QEMU returned the reserved zero event sequence.
    #[error("QEMU fault event returned sequence zero")]
    QemuEventSequenceZero,
    /// A QEMU raw coordinate could not be returned to logical space.
    #[error("QEMU fault result coordinate overflowed logical icount")]
    CoordinateOverflow,
    /// QEMU returned an unknown phase tag.
    #[error("QEMU fault result returned unknown phase {value}")]
    QemuPhase {
        /// Unknown phase.
        value: u16,
    },
    /// QEMU returned an unknown status tag.
    #[error("QEMU fault result returned unknown status {value}")]
    QemuStatus {
        /// Unknown status.
        value: u16,
    },
    /// QEMU returned an unknown event outcome tag.
    #[error("QEMU fault event returned unknown outcome {value}")]
    QemuEventOutcome {
        /// Unknown outcome.
        value: u16,
    },
}

#[cfg(test)]
#[path = "fault_command_test.rs"]
mod tests;
