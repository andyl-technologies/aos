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
    FAULT_COMMAND_SEMANTIC_VERSION, FAULT_REGISTER_CAPABILITY_IMPULSE,
    FAULT_TARGET_MANIFEST_QUERY_V1_BYTES, FaultAbiError, FaultAcceleratorCapabilityManifestV1,
    FaultAcceleratorCapabilityRowV1, FaultBoundaryPhase, FaultCapabilityRowV1,
    FaultCapabilityScope, FaultClockCapabilityManifestV1, FaultClockCapabilityRowV1,
    FaultClockEvidenceV1, FaultClockObservationV1, FaultCommandHeaderV1, FaultCommandKind,
    FaultCommandSlotV1, FaultEventHeaderV1, FaultEventOutcomeV1, FaultEventSlotV1,
    FaultExceptionEvidenceV1, FaultHardwareErrorCapabilityManifestV1,
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
    reserved: u32,
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
    #[allow(dead_code, reason = "cancellation is used by restore rollback wiring")]
    cancel: QemuFaultCancelFn,
    peek: QemuFaultPeekFn,
    poll: QemuFaultPollFn,
    event_peek: QemuFaultEventPeekFn,
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
        fault_capability_manifest_digest(&rows)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;
        Ok(rows)
    }

    fn register_manifest(
        self,
    ) -> Result<FaultRegisterCapabilityManifestV1, FaultCommandBridgeError> {
        let mut architecture = 0_u16;
        let mut cpu_model = std::ptr::null();
        let required =
            (self.register_manifest)(std::ptr::null_mut(), 0, &mut architecture, &mut cpu_model);
        if required > crucible_shmem::HARD_FAULT_TARGET_MANIFEST_ROWS {
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
        FaultRegisterCapabilityManifestV1::decode(
            &manifest
                .encode()
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        )
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
            qemu_build_id: text_digest(qemu_build_id, "qemu_build_id")?,
            qemu_patch_series_hash: text_digest(qemu_patch_series_hash, "qemu_patch_series_hash")?,
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
    static DIGEST: &[u8] = b"1111111111111111111111111111111111111111111111111111111111111111\0";
    if _out.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: the test caller provides one writable row and all referenced
    // strings have static NUL-terminated storage.
    unsafe {
        *_out = QemuFaultSystemManifest {
            semantic_version: 1,
            vmstate_format_version: 1,
            vmstate_section_count: 9,
            reserved: 0,
            vmstate_sections_sha256: [1; 32],
            system_capability: CAPABILITY.as_ptr().cast(),
            vmstate_capability: VMSTATE.as_ptr().cast(),
            qemu_build_id: DIGEST.as_ptr().cast(),
            qemu_patch_series_hash: DIGEST.as_ptr().cast(),
            shmem_header_hash: DIGEST.as_ptr().cast(),
        };
    }
    0
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
extern "C" fn test_event_peek(event: *mut QemuFaultEvent, payload_length: *mut usize) -> c_int {
    if event.is_null() || payload_length.is_null() {
        return -libc::EINVAL;
    }
    0
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
fn test_result_for_command(command: QemuFaultCommand) -> QemuFaultResult {
    QemuFaultResult {
        command_kind: command.command_kind,
        status: FaultResultStatus::Applied as u16,
        phase: command.phase,
        reserved: 0,
        semantic_version: command.semantic_version,
        capability_version: 1,
        command_sequence: command.command_sequence,
        observed_icount: command.target_icount,
        applied_icount: command.target_icount,
        before_hash: [0; 32],
        after_hash: [0; 32],
        evidence_hash: [0; 32],
    }
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
        command_kind: command_kind(raw.command_kind)?,
        semantic_version: raw.semantic_version,
        scope: FaultCapabilityScope::from_u16(raw.scope)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        phase_mask: raw.phase_mask,
        maximum_payload_bytes: raw.maximum_payload_bytes,
        maximum_pending_commands: raw.maximum_pending_commands,
        required_feature_bits: raw.required_feature_bits,
        capability_hash: *hasher.finalize().as_bytes(),
    };
    FaultCapabilityRowV1::decode(&row.encode())
        .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })
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
    Ok(FaultRegisterCapabilityRowV1 {
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
    })
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
    // SAFETY: the sealed QEMU manifest owns a process-lifetime target array;
    // its non-null pointer and hard-bounded element count were checked above.
    let target_vcpus =
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
    pending_command: Option<DequeuedFaultCommand>,
}

impl FaultCommandBridge {
    /// Builds the bridge and snapshots the immutable QEMU capability registry.
    pub(crate) fn new(
        apis: QemuFaultCommandApis,
        target_node_hash: [u8; 32],
        region: &mut MappedSetupRegion,
        vm_slot: u32,
    ) -> Result<Self, FaultCommandBridgeError> {
        if target_node_hash == [0; 32] {
            return Err(FaultCommandBridgeError::ZeroTargetNodeHash);
        }
        let mut rows = apis.capability_rows()?;
        let (register_manifest_payload, register_evidence_identity) = if rows.iter().any(|row| {
            row.command_kind == FaultCommandKind::CpuRegisterTransform
                && row.required_feature_bits & FAULT_CAPABILITY_FEATURE_REGISTER_MUTATION != 0
        }) {
            let manifest = apis.register_manifest()?;
            apis.bind_register_manifest(&manifest)?;
            let payload = manifest
                .encode()
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;
            let manifest_digest = fault_register_manifest_digest_v1(&manifest)
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;
            let evidence_identity = RegisterEvidenceIdentity {
                architecture: manifest.architecture,
                manifest_digest,
                cpu_model_digest: fault_register_cpu_model_digest_v1(
                    manifest.architecture,
                    &manifest.cpu_model,
                ),
                rows: manifest.rows.clone(),
            };
            let register_row = rows
                .iter_mut()
                .find(|row| row.command_kind == FaultCommandKind::CpuRegisterTransform)
                .ok_or(FaultCommandBridgeError::RegisterCapabilityMissing)?;
            register_row.scope = manifest.architecture;
            register_row.capability_hash =
                register_capability_hash(manifest.architecture, manifest_digest);
            (Some(payload), Some(evidence_identity))
        } else {
            (None, None)
        };
        let (interrupt_manifest_payload, interrupt_manifest_digest) = if rows.iter().any(|row| {
            matches!(
                row.command_kind,
                FaultCommandKind::InterruptDisposition | FaultCommandKind::InterruptStorm
            ) && row.required_feature_bits & FAULT_CAPABILITY_FEATURE_INTERRUPT != 0
        }) {
            let manifest = apis.interrupt_manifest()?;
            apis.bind_interrupt_manifest(&manifest)?;
            if register_evidence_identity
                .as_ref()
                .is_some_and(|register| register.architecture != manifest.architecture)
            {
                return Err(FaultCommandBridgeError::InterruptManifestRow);
            }
            let payload = manifest
                .encode()
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;
            (
                Some(payload.clone()),
                Some(*blake3::hash(&payload).as_bytes()),
            )
        } else {
            (None, None)
        };
        let (hardware_error_manifest_payload, hardware_error_manifest_digest) = if rows
            .iter()
            .any(|row| row.required_feature_bits & FAULT_CAPABILITY_FEATURE_HARDWARE_ERROR != 0)
        {
            let manifest = apis.hardware_error_manifest()?;
            apis.bind_hardware_error_manifest(&manifest)?;
            if register_evidence_identity
                .as_ref()
                .is_some_and(|register| register.architecture != manifest.architecture)
            {
                return Err(FaultCommandBridgeError::HardwareErrorManifestRow);
            }
            let payload = manifest
                .encode()
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;
            (
                Some(payload.clone()),
                Some(*blake3::hash(&payload).as_bytes()),
            )
        } else {
            (None, None)
        };
        let (clock_manifest_payload, clock_manifest_digest) = if rows
            .iter()
            .any(|row| row.required_feature_bits & FAULT_CAPABILITY_FEATURE_GUEST_CLOCK != 0)
        {
            let manifest = apis.clock_manifest()?;
            apis.bind_clock_manifest(&manifest)?;
            if register_evidence_identity
                .as_ref()
                .is_some_and(|register| register.architecture != manifest.architecture)
            {
                return Err(FaultCommandBridgeError::ClockManifestRow);
            }
            let payload = manifest
                .encode()
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;
            (
                Some(payload.clone()),
                Some(*blake3::hash(&payload).as_bytes()),
            )
        } else {
            (None, None)
        };
        let (accelerator_manifest_payload, accelerator_manifest_digest) =
            match apis.accelerator_manifest()? {
                Some(manifest) => {
                    let payload = manifest
                        .encode()
                        .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;
                    (
                        Some(payload.clone()),
                        Some(*blake3::hash(&payload).as_bytes()),
                    )
                }
                None => (None, None),
            };
        let system_manifest_payload = apis
            .system_manifest()?
            .encode()
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?
            .to_vec();
        if let Some(register) = register_evidence_identity.as_ref() {
            rows.push(target_manifest_capability_row(
                register.architecture,
                register.manifest_digest,
                interrupt_manifest_digest,
                hardware_error_manifest_digest,
                clock_manifest_digest,
                accelerator_manifest_digest,
            ));
            rows.sort_by_key(|row| {
                (
                    row.command_kind as u16,
                    row.semantic_version,
                    row.scope as u16,
                )
            });
            fault_capability_manifest_digest(&rows)
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;
        }
        let instruction_evidence_identity = if rows.iter().any(|row| {
            matches!(
                row.command_kind,
                FaultCommandKind::CpuInstructionTransform | FaultCommandKind::CpuException
            ) && row.required_feature_bits & FAULT_CAPABILITY_FEATURE_INSTRUCTION != 0
        }) {
            let identity = apis.instruction_manifest()?;
            if register_evidence_identity
                .as_ref()
                .is_some_and(|register| register.architecture != identity.architecture)
            {
                return Err(FaultCommandBridgeError::InstructionManifestChanged);
            }
            Some(identity)
        } else {
            None
        };
        let capability_payload = encode_fault_capability_manifest(&rows)
            .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?;
        let commands = StableFaultCommandTransport::new(
            region
                .fault_command_transport_mut(vm_slot)
                .map_err(|source| FaultCommandBridgeError::MappedTransport { source })?,
        )?;
        let results = StableFaultResultTransport::new(
            region
                .fault_result_transport_mut(vm_slot)
                .map_err(|source| FaultCommandBridgeError::MappedTransport { source })?,
        )?;
        let events = StableFaultEventTransport::new(
            region
                .fault_event_transport_mut(vm_slot)
                .map_err(|source| FaultCommandBridgeError::MappedTransport { source })?,
        )?;
        Ok(Self {
            apis,
            target_node_hash,
            commands,
            results,
            events,
            last_sequence: 0,
            capability_payload,
            capability_queries: BTreeSet::new(),
            register_manifest_payload,
            interrupt_manifest_payload,
            hardware_error_manifest_payload,
            clock_manifest_payload,
            accelerator_manifest_payload,
            system_manifest_payload,
            register_evidence_identity,
            instruction_evidence_identity,
            register_commands: BTreeMap::new(),
            active_register_bindings: BTreeMap::new(),
            instruction_commands: BTreeMap::new(),
            active_instruction_bindings: BTreeMap::new(),
            exception_commands: BTreeMap::new(),
            memory_ecc_commands: BTreeMap::new(),
            clock_commands: BTreeMap::new(),
            active_clock_bindings: BTreeMap::new(),
            accelerator_commands: BTreeMap::new(),
            active_accelerator_bindings: BTreeMap::new(),
            pending_command: None,
        })
    }

    /// Drains completed results, submits every published command, then drains
    /// synchronous QEMU rejections.
    ///
    /// `logical_icount_offset` is the scheduler logical coordinate minus QEMU's
    /// raw retired count and must be the same offset used by the sim-loop
    /// authorization ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`FaultCommandBridgeError`] for malformed transport framing,
    /// missing/changed capabilities, coordinate overflow, QEMU API failure, or
    /// lossless result-publication failure.
    pub(crate) fn pump(
        &mut self,
        logical_icount_offset: u64,
        raw_icount: u64,
    ) -> Result<(), FaultCommandBridgeError> {
        let logical_icount = raw_icount
            .checked_add(logical_icount_offset)
            .ok_or(FaultCommandBridgeError::CoordinateOverflow)?;
        if !self.poll_results(logical_icount_offset)? {
            return Ok(());
        }
        if !self.poll_events(logical_icount_offset)? {
            return Ok(());
        }
        loop {
            let command = match self.pending_command.take() {
                Some(command) => command,
                None => {
                    let Some(command) = self.commands.dequeue()? else {
                        break;
                    };
                    command
                }
            };
            let required_result_payload = match &command {
                DequeuedFaultCommand::Valid { header, payload }
                    if header.command_kind == FaultCommandKind::QueryTargetManifest =>
                {
                    let query = FaultTargetManifestQueryV1::decode(payload).ok();
                    match query.map(|query| query.kind) {
                        Some(FaultTargetManifestKind::Register) => {
                            self.register_manifest_payload.as_ref().map_or(0, Vec::len)
                        }
                        Some(FaultTargetManifestKind::Interrupt) => {
                            self.interrupt_manifest_payload.as_ref().map_or(0, Vec::len)
                        }
                        Some(FaultTargetManifestKind::HardwareError) => self
                            .hardware_error_manifest_payload
                            .as_ref()
                            .map_or(0, Vec::len),
                        Some(FaultTargetManifestKind::Clock) => {
                            self.clock_manifest_payload.as_ref().map_or(0, Vec::len)
                        }
                        Some(FaultTargetManifestKind::Accelerator) => self
                            .accelerator_manifest_payload
                            .as_ref()
                            .map_or(0, Vec::len),
                        Some(FaultTargetManifestKind::System) => self.system_manifest_payload.len(),
                        None => 0,
                    }
                }
                DequeuedFaultCommand::Valid { .. } | DequeuedFaultCommand::Rejected { .. } => 0,
            };
            if !self.results.can_enqueue(required_result_payload)? {
                self.pending_command = Some(command);
                return Ok(());
            }
            match command {
                DequeuedFaultCommand::Valid { header, payload } => {
                    self.submit(*header, &payload, logical_icount_offset, logical_icount)?;
                }
                DequeuedFaultCommand::Rejected {
                    raw_command_kind,
                    command_sequence,
                    error,
                } => {
                    if command_sequence == 0 {
                        return Err(FaultCommandBridgeError::UncorrelatableMalformedCommand);
                    }
                    self.publish_local_rejection(
                        raw_command_kind,
                        command_sequence,
                        FaultBoundaryPhase::NodeBoundary,
                        rejection_status(error),
                        logical_icount,
                    )?;
                }
            }
            // Preserve the earliest QEMU completion point before a later
            // locally rejected command can publish ahead of it.
            if !self.poll_results(logical_icount_offset)? {
                return Ok(());
            }
            if !self.poll_events(logical_icount_offset)? {
                return Ok(());
            }
        }
        if self.poll_results(logical_icount_offset)? {
            let _drained = self.poll_events(logical_icount_offset)?;
        }
        Ok(())
    }

    fn submit(
        &mut self,
        header: FaultCommandHeaderV1,
        payload: &[u8],
        logical_icount_offset: u64,
        logical_icount: u64,
    ) -> Result<(), FaultCommandBridgeError> {
        if header.command_sequence <= self.last_sequence {
            return self.publish_local_rejection(
                header.command_kind as u16,
                header.command_sequence,
                header.phase,
                FaultResultStatus::DuplicateSequence,
                logical_icount,
            );
        }
        self.last_sequence = header.command_sequence;
        if header.target_node_hash != self.target_node_hash {
            return self.publish_local_rejection(
                header.command_kind as u16,
                header.command_sequence,
                header.phase,
                FaultResultStatus::InvalidTarget,
                logical_icount,
            );
        }
        if header.command_kind == FaultCommandKind::QueryTargetManifest {
            let query = match FaultTargetManifestQueryV1::decode(payload) {
                Ok(query) => query,
                Err(_source) => {
                    return self.publish_local_rejection(
                        header.command_kind as u16,
                        header.command_sequence,
                        header.phase,
                        FaultResultStatus::MalformedCommand,
                        logical_icount,
                    );
                }
            };
            if header.phase != FaultBoundaryPhase::NodeBoundary
                || header.target_icount != 0
                || header.authorization_ceiling_icount != 0
                || logical_icount != 0
            {
                return self.publish_local_rejection(
                    header.command_kind as u16,
                    header.command_sequence,
                    header.phase,
                    FaultResultStatus::InvalidPhase,
                    logical_icount,
                );
            }
            let result_payload = match query.kind {
                FaultTargetManifestKind::Register => self.register_manifest_payload.clone(),
                FaultTargetManifestKind::Interrupt => self.interrupt_manifest_payload.clone(),
                FaultTargetManifestKind::HardwareError => {
                    self.hardware_error_manifest_payload.clone()
                }
                FaultTargetManifestKind::Clock => self.clock_manifest_payload.clone(),
                FaultTargetManifestKind::Accelerator => self.accelerator_manifest_payload.clone(),
                FaultTargetManifestKind::System => Some(self.system_manifest_payload.clone()),
            };
            let Some(result_payload) = result_payload else {
                return self.publish_local_rejection(
                    header.command_kind as u16,
                    header.command_sequence,
                    header.phase,
                    FaultResultStatus::UnsupportedCapability,
                    logical_icount,
                );
            };
            return self.publish_local_applied(
                header.command_kind as u16,
                header.command_sequence,
                header.phase,
                logical_icount,
                &result_payload,
            );
        }
        let register_expectation = if header.command_kind == FaultCommandKind::CpuRegisterTransform
        {
            let identity = self
                .register_evidence_identity
                .as_ref()
                .ok_or(FaultCommandBridgeError::RegisterEvidence)?;
            Some(register_command_expectation(
                payload,
                header.binding_hash,
                identity,
            )?)
        } else {
            None
        };
        let instruction_expectation =
            if header.command_kind == FaultCommandKind::CpuInstructionTransform {
                let identity = self
                    .register_evidence_identity
                    .as_ref()
                    .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
                Some(instruction_command_expectation(
                    payload,
                    header.binding_hash,
                    identity,
                )?)
            } else {
                None
            };
        let exception_expectation = if header.command_kind == FaultCommandKind::CpuException {
            Some(exception_command_expectation(payload, header.binding_hash)?)
        } else {
            None
        };
        let memory_ecc_expectation = if header.command_kind == FaultCommandKind::MemoryEccEvent {
            Some(memory_ecc_command_expectation(
                payload,
                header.binding_hash,
            )?)
        } else {
            None
        };
        let clock_expectation = if matches!(
            header.command_kind,
            FaultCommandKind::ClockTransform | FaultCommandKind::ClockSourceState
        ) {
            Some(clock_command_expectation(
                payload,
                header.binding_hash,
                header.command_kind,
            )?)
        } else {
            None
        };
        let accelerator_expectation = if matches!(
            header.command_kind,
            FaultCommandKind::AcceleratorLifecycle
                | FaultCommandKind::AcceleratorResultTransform
                | FaultCommandKind::AcceleratorMemoryEvent
                | FaultCommandKind::AcceleratorService
        ) {
            Some(accelerator_command_expectation(
                payload,
                header.binding_hash,
                header.command_kind,
            )?)
        } else {
            None
        };
        let Some(target_icount) = header.target_icount.checked_sub(logical_icount_offset) else {
            return self.publish_local_rejection(
                header.command_kind as u16,
                header.command_sequence,
                header.phase,
                FaultResultStatus::PastBoundary,
                logical_icount,
            );
        };
        let Some(authorization_ceiling_icount) = header
            .authorization_ceiling_icount
            .checked_sub(logical_icount_offset)
        else {
            return self.publish_local_rejection(
                header.command_kind as u16,
                header.command_sequence,
                header.phase,
                FaultResultStatus::PastBoundary,
                logical_icount,
            );
        };
        if header.command_kind == FaultCommandKind::QueryCapabilities {
            self.capability_queries.insert(header.command_sequence);
        }
        let command = QemuFaultCommand {
            abi_major: header.abi_major,
            abi_minor: header.abi_minor,
            command_kind: header.command_kind as u16,
            command_flags: header.command_flags,
            phase: header.phase as u16,
            reserved: 0,
            semantic_version: header.semantic_version,
            command_sequence: header.command_sequence,
            target_node_hash: header.target_node_hash,
            target_icount,
            authorization_ceiling_icount,
            binding_hash: header.binding_hash,
            opportunity_hash: header.opportunity_hash,
            expected_precondition_hash: header.expected_precondition_hash,
        };
        let payload_pointer = if payload.is_empty() {
            std::ptr::null()
        } else {
            payload.as_ptr()
        };
        let status = (self.apis.submit)(&command, payload_pointer, payload.len());
        if status != 0 {
            self.capability_queries.remove(&header.command_sequence);
            return Err(FaultCommandBridgeError::QemuSubmit { status });
        }
        if let Some(expectation) = register_expectation {
            self.register_commands
                .insert(header.command_sequence, expectation);
        }
        if let Some(expectation) = instruction_expectation {
            self.instruction_commands
                .insert(header.command_sequence, expectation);
        }
        if let Some(expectation) = exception_expectation {
            self.exception_commands
                .insert(header.command_sequence, expectation);
        }
        if let Some(expectation) = memory_ecc_expectation {
            self.memory_ecc_commands
                .insert(header.command_sequence, expectation);
        }
        if let Some(expectation) = clock_expectation {
            self.clock_commands
                .insert(header.command_sequence, expectation);
        }
        if let Some(expectation) = accelerator_expectation {
            self.accelerator_commands
                .insert(header.command_sequence, expectation);
        }
        Ok(())
    }

    fn poll_results(
        &mut self,
        logical_icount_offset: u64,
    ) -> Result<bool, FaultCommandBridgeError> {
        let payload_capacity = usize::try_from(HARD_FAULT_PAYLOAD_BYTES)
            .map_err(|_source| FaultCommandBridgeError::PayloadCapacity)?;
        loop {
            let mut peeked = QemuFaultResult::default();
            let mut peeked_payload_len = 0_usize;
            let status = (self.apis.peek)(&mut peeked, &mut peeked_payload_len);
            if status == 0 {
                return Ok(true);
            }
            if status != 1 {
                return Err(FaultCommandBridgeError::QemuPeek { status });
            }
            if peeked_payload_len > payload_capacity {
                return Err(FaultCommandBridgeError::QemuPayloadLength {
                    length: peeked_payload_len,
                    capacity: payload_capacity,
                });
            }
            let is_capability_query = self.capability_queries.contains(&peeked.command_sequence)
                && peeked.status == FaultResultStatus::Applied as u16;
            let is_register_result = peeked.command_kind
                == FaultCommandKind::CpuRegisterTransform as u16
                && peeked.status == FaultResultStatus::Applied as u16
                && self.register_evidence_identity.is_some();
            let result_payload_len = if is_capability_query {
                self.capability_payload.len()
            } else if is_register_result {
                peeked_payload_len
                    .checked_add(128)
                    .ok_or(FaultCommandBridgeError::PayloadCapacity)?
            } else {
                peeked_payload_len
            };
            if !self.results.can_enqueue(result_payload_len)? {
                return Ok(false);
            }
            let mut payload = vec![0_u8; peeked_payload_len];
            let mut result = QemuFaultResult::default();
            let mut payload_len = 0_usize;
            let payload_pointer = if payload.is_empty() {
                std::ptr::null_mut()
            } else {
                payload.as_mut_ptr()
            };
            let status = (self.apis.poll)(
                &mut result,
                payload_pointer,
                payload.len(),
                &mut payload_len,
            );
            if status != 1 {
                return Err(FaultCommandBridgeError::QemuPoll { status });
            }
            if result.command_sequence != peeked.command_sequence || result != peeked {
                return Err(FaultCommandBridgeError::QemuPeekChanged {
                    expected_sequence: peeked.command_sequence,
                    observed_sequence: result.command_sequence,
                });
            }
            if payload_len != peeked_payload_len {
                return Err(FaultCommandBridgeError::QemuPayloadLengthChanged {
                    expected: peeked_payload_len,
                    observed: payload_len,
                });
            }
            let mut result_payload = &payload[..];
            let translated_register: Vec<u8>;
            let translated_clock: Vec<u8>;
            let register_command = self
                .register_commands
                .get(&result.command_sequence)
                .cloned();
            if is_capability_query {
                self.capability_queries.remove(&result.command_sequence);
                result_payload = &self.capability_payload;
                result.evidence_hash = *blake3::hash(result_payload).as_bytes();
            } else if is_register_result && payload.starts_with(b"CRUCQRW1") {
                let identity = self
                    .register_evidence_identity
                    .as_ref()
                    .ok_or(FaultCommandBridgeError::RegisterEvidence)?;
                translated_register = translate_register_evidence(
                    &payload,
                    identity,
                    logical_icount_offset,
                    result.applied_icount,
                    None,
                    result.before_hash,
                    result.after_hash,
                    register_command
                        .as_ref()
                        .and_then(|command| command.mutation.as_ref())
                        .ok_or(FaultCommandBridgeError::RegisterEvidence)?,
                )?;
                result_payload = &translated_register;
                result.evidence_hash = *blake3::hash(result_payload).as_bytes();
            } else if result.command_kind == FaultCommandKind::ClockTransform as u16
                && payload.starts_with(b"CRUCCIM1")
            {
                translated_clock = translate_clock_impulse_evidence(
                    &payload,
                    self.clock_manifest_payload
                        .as_deref()
                        .ok_or(FaultCommandBridgeError::ClockEvidence)?,
                    &result,
                    logical_icount_offset,
                    self.clock_commands
                        .get(&result.command_sequence)
                        .ok_or(FaultCommandBridgeError::ClockEvidence)?,
                )?;
                result_payload = &translated_clock;
                result.evidence_hash = *blake3::hash(result_payload).as_bytes();
            }
            let observed_icount = result
                .observed_icount
                .checked_add(logical_icount_offset)
                .ok_or(FaultCommandBridgeError::CoordinateOverflow)?;
            let applied_icount = if result.applied_icount == 0 {
                0
            } else {
                result
                    .applied_icount
                    .checked_add(logical_icount_offset)
                    .ok_or(FaultCommandBridgeError::CoordinateOverflow)?
            };
            let header = FaultResultHeaderV1 {
                abi_major: crucible_shmem::FAULT_COMMAND_ABI_MAJOR,
                abi_minor: crucible_shmem::FAULT_COMMAND_ABI_MINOR,
                command_kind: result.command_kind,
                status: result_status(result.status)?,
                semantic_version: result.semantic_version,
                command_sequence: result.command_sequence,
                observed_icount,
                applied_icount,
                capability_version: result.capability_version,
                phase: boundary_phase(result.phase)?,
                before_hash: result.before_hash,
                after_hash: result.after_hash,
                evidence_hash: result.evidence_hash,
                result_payload_hash: [0; 32],
                result_offset: 0,
                result_length: 0,
            };
            self.results.enqueue(header, result_payload)?;
            if result.command_kind == FaultCommandKind::CpuRegisterTransform as u16 {
                let Some(command) = register_command else {
                    return Err(FaultCommandBridgeError::RegisterEvidence);
                };
                if result.status == FaultResultStatus::Applied as u16 {
                    match command.operation {
                        NodeFaultOperationV1::Upsert => {
                            if let Some(prior) = self
                                .active_register_bindings
                                .insert(command.binding_hash, result.command_sequence)
                            {
                                if prior != result.command_sequence {
                                    self.register_commands.remove(&prior);
                                }
                            }
                        }
                        NodeFaultOperationV1::Remove => {
                            if let Some(prior) =
                                self.active_register_bindings.remove(&command.binding_hash)
                            {
                                self.register_commands.remove(&prior);
                            }
                            self.register_commands.remove(&result.command_sequence);
                        }
                        NodeFaultOperationV1::Apply => {}
                    }
                } else {
                    self.register_commands.remove(&result.command_sequence);
                }
            }
            if result.command_kind == FaultCommandKind::CpuInstructionTransform as u16 {
                track_instruction_result(
                    &mut self.instruction_commands,
                    &mut self.active_instruction_bindings,
                    result.command_sequence,
                    result.status,
                )?;
            }
            if result.command_kind == FaultCommandKind::CpuException as u16
                && result.status != FaultResultStatus::Applied as u16
            {
                self.exception_commands.remove(&result.command_sequence);
            }
            if result.command_kind == FaultCommandKind::MemoryEccEvent as u16
                && result.status != FaultResultStatus::Applied as u16
            {
                self.memory_ecc_commands.remove(&result.command_sequence);
            }
            if matches!(
                result.command_kind,
                value if value == FaultCommandKind::ClockTransform as u16
                    || value == FaultCommandKind::ClockSourceState as u16
            ) {
                let command = self
                    .clock_commands
                    .get(&result.command_sequence)
                    .cloned()
                    .ok_or(FaultCommandBridgeError::ClockEvidence)?;
                if result.status == FaultResultStatus::Applied as u16 {
                    match command.operation {
                        NodeFaultOperationV1::Upsert => {
                            let _prior = self
                                .active_clock_bindings
                                .insert(command.binding_hash, result.command_sequence);
                        }
                        NodeFaultOperationV1::Remove => {
                            let _prior = self.active_clock_bindings.remove(&command.binding_hash);
                            self.clock_commands.remove(&result.command_sequence);
                        }
                        NodeFaultOperationV1::Apply => {}
                    }
                } else {
                    self.clock_commands.remove(&result.command_sequence);
                }
            }
            if matches!(
                result.command_kind,
                value if value == FaultCommandKind::AcceleratorLifecycle as u16
                    || value == FaultCommandKind::AcceleratorResultTransform as u16
                    || value == FaultCommandKind::AcceleratorMemoryEvent as u16
                    || value == FaultCommandKind::AcceleratorService as u16
            ) {
                let command = self
                    .accelerator_commands
                    .get(&result.command_sequence)
                    .cloned()
                    .ok_or(FaultCommandBridgeError::AcceleratorEvidence)?;
                if result.status == FaultResultStatus::Applied as u16 {
                    match command.operation {
                        NodeFaultOperationV1::Upsert => {
                            if let Some(prior) = self
                                .active_accelerator_bindings
                                .insert(command.binding_hash, result.command_sequence)
                                && prior != result.command_sequence
                            {
                                self.accelerator_commands.remove(&prior);
                            }
                        }
                        NodeFaultOperationV1::Remove => {
                            if let Some(prior) = self
                                .active_accelerator_bindings
                                .remove(&command.binding_hash)
                            {
                                self.accelerator_commands.remove(&prior);
                            }
                            self.accelerator_commands.remove(&result.command_sequence);
                        }
                        NodeFaultOperationV1::Apply => {}
                    }
                } else {
                    self.accelerator_commands.remove(&result.command_sequence);
                }
            }
        }
    }

    fn poll_events(&mut self, logical_icount_offset: u64) -> Result<bool, FaultCommandBridgeError> {
        let payload_capacity = usize::try_from(HARD_FAULT_PAYLOAD_BYTES)
            .map_err(|_source| FaultCommandBridgeError::PayloadCapacity)?;
        loop {
            let mut peeked = QemuFaultEvent::default();
            let mut peeked_payload_len = 0_usize;
            let status = (self.apis.event_peek)(&mut peeked, &mut peeked_payload_len);
            if status == 0 {
                let active: BTreeSet<u64> = self.active_clock_bindings.values().copied().collect();
                self.clock_commands.retain(|sequence, command| {
                    command.operation != NodeFaultOperationV1::Upsert || active.contains(sequence)
                });
                return Ok(true);
            }
            if status != 1 {
                return Err(FaultCommandBridgeError::QemuEventPeek { status });
            }
            if peeked_payload_len == 0 || peeked_payload_len > payload_capacity {
                return Err(FaultCommandBridgeError::QemuEventPayloadLength {
                    length: peeked_payload_len,
                    capacity: payload_capacity,
                });
            }
            let published_payload_len = if matches!(
                peeked.command_kind,
                value if value == FaultCommandKind::CpuRegisterTransform as u16
                    || value == FaultCommandKind::CpuInstructionTransform as u16
            ) {
                peeked_payload_len
                    .checked_add(128)
                    .ok_or(FaultCommandBridgeError::PayloadCapacity)?
            } else {
                peeked_payload_len
            };
            if !self.events.can_enqueue(published_payload_len)? {
                return Ok(false);
            }
            let mut payload = vec![0_u8; peeked_payload_len];
            let mut event = QemuFaultEvent::default();
            let mut payload_len = 0_usize;
            let status = (self.apis.event_poll)(
                &mut event,
                payload.as_mut_ptr(),
                payload.len(),
                &mut payload_len,
            );
            if status != 1 {
                return Err(FaultCommandBridgeError::QemuEventPoll { status });
            }
            if event != peeked {
                return Err(FaultCommandBridgeError::QemuEventPeekChanged {
                    expected_sequence: peeked.event_sequence,
                    observed_sequence: event.event_sequence,
                });
            }
            if payload_len != peeked_payload_len {
                return Err(FaultCommandBridgeError::QemuEventPayloadLengthChanged {
                    expected: peeked_payload_len,
                    observed: payload_len,
                });
            }
            if event.reserved != 0 {
                return Err(FaultCommandBridgeError::QemuEventReserved);
            }
            if event.event_sequence == 0 {
                return Err(FaultCommandBridgeError::QemuEventSequenceZero);
            }
            let observed_icount = event
                .observed_icount
                .checked_add(logical_icount_offset)
                .ok_or(FaultCommandBridgeError::CoordinateOverflow)?;
            let register_command = self
                .register_commands
                .get(&event.rule_command_sequence)
                .cloned();
            if register_command
                .as_ref()
                .is_some_and(|command| command.binding_hash != event.binding_hash)
            {
                return Err(FaultCommandBridgeError::RegisterEvidence);
            }
            let instruction_command = self
                .instruction_commands
                .get(&event.rule_command_sequence)
                .cloned();
            let exception_command = self
                .exception_commands
                .get(&event.rule_command_sequence)
                .cloned();
            let memory_ecc_command = self
                .memory_ecc_commands
                .get(&event.rule_command_sequence)
                .cloned();
            let clock_command = self
                .clock_commands
                .get(&event.rule_command_sequence)
                .cloned();
            let accelerator_command = self
                .accelerator_commands
                .get(&event.rule_command_sequence)
                .cloned();
            let instruction_terminal = event.command_kind
                == FaultCommandKind::CpuInstructionTransform as u16
                && FaultTerminalEvidenceV1::has_magic(&payload);
            let published_payload =
                if event.command_kind == FaultCommandKind::CpuRegisterTransform as u16 {
                    let identity = self
                        .register_evidence_identity
                        .as_ref()
                        .ok_or(FaultCommandBridgeError::RegisterEvidence)?;
                    translate_register_evidence(
                        &payload,
                        identity,
                        logical_icount_offset,
                        event.observed_icount,
                        Some(event.model_phase),
                        event.before_hash,
                        event.after_hash,
                        register_command
                            .as_ref()
                            .and_then(|command| command.mutation.as_ref())
                            .ok_or(FaultCommandBridgeError::RegisterEvidence)?,
                    )?
                } else if event.command_kind == FaultCommandKind::CpuInstructionTransform as u16 {
                    let command = instruction_command
                        .as_ref()
                        .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
                    if instruction_terminal {
                        translate_terminal_instruction_evidence(&payload, &event, command)?
                    } else {
                        translate_instruction_evidence(
                            &payload,
                            self.instruction_evidence_identity
                                .as_ref()
                                .ok_or(FaultCommandBridgeError::InstructionEvidence)?,
                            self.register_evidence_identity
                                .as_ref()
                                .ok_or(FaultCommandBridgeError::InstructionEvidence)?,
                            logical_icount_offset,
                            &event,
                            command,
                        )?
                    }
                } else if event.command_kind == FaultCommandKind::CpuException as u16 {
                    let command = exception_command
                        .as_ref()
                        .ok_or(FaultCommandBridgeError::ExceptionEvidence)?;
                    if payload.len() == 648 {
                        translate_hardware_exception_evidence(
                            &payload,
                            self.hardware_error_manifest_payload
                                .as_deref()
                                .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?,
                            &event,
                            command,
                        )?
                    } else {
                        translate_exception_evidence(
                            &payload,
                            self.instruction_evidence_identity
                                .as_ref()
                                .ok_or(FaultCommandBridgeError::ExceptionEvidence)?,
                            logical_icount_offset,
                            &event,
                            command,
                        )?
                    }
                } else if event.command_kind == FaultCommandKind::MemoryEccEvent as u16 {
                    translate_hardware_ecc_evidence(
                        &payload,
                        self.hardware_error_manifest_payload
                            .as_deref()
                            .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?,
                        &event,
                        memory_ecc_command
                            .as_ref()
                            .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?,
                    )?
                } else if event.command_kind == FaultCommandKind::ClockTransform as u16
                    || event.command_kind == FaultCommandKind::ClockSourceState as u16
                {
                    translate_clock_evidence(
                        &payload,
                        self.clock_manifest_payload
                            .as_deref()
                            .ok_or(FaultCommandBridgeError::ClockEvidence)?,
                        &event,
                        observed_icount,
                        clock_command
                            .as_ref()
                            .ok_or(FaultCommandBridgeError::ClockEvidence)?,
                    )?
                } else if matches!(
                    event.command_kind,
                    value if value == FaultCommandKind::AcceleratorLifecycle as u16
                        || value == FaultCommandKind::AcceleratorResultTransform as u16
                        || value == FaultCommandKind::AcceleratorMemoryEvent as u16
                        || value == FaultCommandKind::AcceleratorService as u16
                ) {
                    translate_accelerator_evidence(
                        &payload,
                        &event,
                        self.accelerator_manifest_payload
                            .as_deref()
                            .ok_or(FaultCommandBridgeError::AcceleratorEvidence)?,
                        accelerator_command
                            .as_ref()
                            .ok_or(FaultCommandBridgeError::AcceleratorEvidence)?,
                    )?
                } else {
                    payload
                };
            if event.command_kind == FaultCommandKind::CpuInstructionTransform as u16 {
                if instruction_terminal {
                    track_terminal_instruction_event(
                        &mut self.instruction_commands,
                        &mut self.active_instruction_bindings,
                        event.rule_command_sequence,
                    )?;
                } else {
                    track_instruction_event(
                        &mut self.instruction_commands,
                        event.rule_command_sequence,
                        &published_payload,
                    )?;
                }
            }
            let header = FaultEventHeaderV1 {
                command_kind: command_kind(event.command_kind)?,
                outcome: event_outcome(event.outcome)?,
                event_sequence: event.event_sequence,
                rule_command_sequence: event.rule_command_sequence,
                observed_icount,
                model_phase: event.model_phase,
                target_kind: event.target_kind,
                generation: event.generation,
                binding_hash: event.binding_hash,
                opportunity_hash: event.opportunity_hash,
                action_hash: event.action_hash,
                target_hash: event.target_hash,
                before_hash: event.before_hash,
                after_hash: event.after_hash,
                evidence_hash: [0; 32],
                payload_hash: [0; 32],
                payload_offset: 0,
                payload_length: 0,
            };
            self.events.enqueue(header, &published_payload)?;
            if let Some(command) = register_command {
                if command.operation == NodeFaultOperationV1::Apply {
                    self.register_commands.remove(&event.rule_command_sequence);
                }
            }
            if event.command_kind == FaultCommandKind::CpuException as u16 {
                self.exception_commands.remove(&event.rule_command_sequence);
            }
            if event.command_kind == FaultCommandKind::MemoryEccEvent as u16 {
                self.memory_ecc_commands
                    .remove(&event.rule_command_sequence);
            }
            if clock_command
                .as_ref()
                .is_some_and(|command| command.operation == NodeFaultOperationV1::Apply)
            {
                self.clock_commands.remove(&event.rule_command_sequence);
            }
            if accelerator_command
                .as_ref()
                .is_some_and(|command| command.operation == NodeFaultOperationV1::Apply)
            {
                self.accelerator_commands
                    .remove(&event.rule_command_sequence);
            }
        }
    }

    fn publish_local_rejection(
        &mut self,
        command_kind: u16,
        command_sequence: u64,
        phase: FaultBoundaryPhase,
        status: FaultResultStatus,
        logical_icount: u64,
    ) -> Result<(), FaultCommandBridgeError> {
        let header = FaultResultHeaderV1 {
            abi_major: crucible_shmem::FAULT_COMMAND_ABI_MAJOR,
            abi_minor: crucible_shmem::FAULT_COMMAND_ABI_MINOR,
            command_kind,
            status,
            semantic_version: crucible_shmem::FAULT_COMMAND_SEMANTIC_VERSION,
            command_sequence,
            observed_icount: logical_icount,
            applied_icount: 0,
            capability_version: 1,
            phase,
            before_hash: [0; 32],
            after_hash: [0; 32],
            evidence_hash: [0; 32],
            result_payload_hash: [0; 32],
            result_offset: 0,
            result_length: 0,
        };
        self.results.enqueue(header, &[])
    }

    fn publish_local_applied(
        &mut self,
        command_kind: u16,
        command_sequence: u64,
        phase: FaultBoundaryPhase,
        logical_icount: u64,
        payload: &[u8],
    ) -> Result<(), FaultCommandBridgeError> {
        let header = FaultResultHeaderV1 {
            abi_major: crucible_shmem::FAULT_COMMAND_ABI_MAJOR,
            abi_minor: crucible_shmem::FAULT_COMMAND_ABI_MINOR,
            command_kind,
            status: FaultResultStatus::Applied,
            semantic_version: crucible_shmem::FAULT_COMMAND_SEMANTIC_VERSION,
            command_sequence,
            observed_icount: logical_icount,
            applied_icount: logical_icount,
            capability_version: 1,
            phase,
            before_hash: [0; 32],
            after_hash: [0; 32],
            evidence_hash: *blake3::hash(payload).as_bytes(),
            result_payload_hash: [0; 32],
            result_offset: 0,
            result_length: 0,
        };
        self.results.enqueue(header, payload)
    }
}

/// Updates bridge-side instruction expectations after QEMU publishes a command result.
///
/// A terminal one-shot `Apply` result deliberately retains its expectation until
/// the corresponding applied or fail-closed evidence event has been translated
/// and published.
fn track_instruction_result(
    commands: &mut BTreeMap<u64, InstructionCommandExpectation>,
    active_bindings: &mut BTreeMap<[u8; 32], u64>,
    command_sequence: u64,
    status: u16,
) -> Result<(), FaultCommandBridgeError> {
    let command = commands
        .get(&command_sequence)
        .cloned()
        .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
    if status == FaultResultStatus::Applied as u16 {
        match command.operation {
            NodeFaultOperationV1::Upsert => {
                if let Some(prior) = active_bindings.insert(command.binding_hash, command_sequence)
                {
                    if prior != command_sequence {
                        commands.remove(&prior);
                    }
                }
            }
            NodeFaultOperationV1::Remove => {
                if let Some(prior) = active_bindings.remove(&command.binding_hash) {
                    commands.remove(&prior);
                }
                commands.remove(&command_sequence);
            }
            NodeFaultOperationV1::Apply => {}
        }
    } else if command.operation != NodeFaultOperationV1::Apply
        || status != FaultResultStatus::InternalError as u16
    {
        commands.remove(&command_sequence);
    }
    Ok(())
}

/// Advances exact replay-event correlation and releases terminal one-shot state.
fn track_instruction_event(
    commands: &mut BTreeMap<u64, InstructionCommandExpectation>,
    command_sequence: u64,
    payload: &[u8],
) -> Result<(), FaultCommandBridgeError> {
    let evidence = FaultInstructionEvidenceV1::decode(payload)
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    let command = commands
        .get_mut(&command_sequence)
        .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
    if evidence.replay_ordinal != command.next_replay_ordinal
        || evidence.replay_total != command.replay_total
    {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    let terminal = evidence.outcome != FaultInstructionEvidenceOutcomeV1::Applied
        || evidence.mutation_kind != FaultInstructionMutationKindV1::Replay
        || evidence.replay_ordinal == evidence.replay_total;
    if terminal {
        if command.operation == NodeFaultOperationV1::Apply {
            commands.remove(&command_sequence);
        } else {
            command.next_replay_ordinal = 0;
        }
    } else {
        command.next_replay_ordinal = command
            .next_replay_ordinal
            .checked_add(1)
            .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
    }
    Ok(())
}

/// Releases the command identity correlated with one global terminal event.
fn track_terminal_instruction_event(
    commands: &mut BTreeMap<u64, InstructionCommandExpectation>,
    active_bindings: &mut BTreeMap<[u8; 32], u64>,
    command_sequence: u64,
) -> Result<(), FaultCommandBridgeError> {
    let command = commands
        .remove(&command_sequence)
        .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
    if active_bindings.get(&command.binding_hash) == Some(&command_sequence) {
        active_bindings.remove(&command.binding_hash);
    }
    Ok(())
}

fn target_manifest_capability_row(
    architecture: FaultCapabilityScope,
    register_manifest_digest: [u8; 32],
    interrupt_manifest_digest: Option<[u8; 32]>,
    hardware_error_manifest_digest: Option<[u8; 32]>,
    clock_manifest_digest: Option<[u8; 32]>,
    accelerator_manifest_digest: Option<[u8; 32]>,
) -> FaultCapabilityRowV1 {
    let name = b"qemu.target-manifest.node.v1";
    let schema = b"crucible.target-manifest-query.v1;kinds=register,interrupt,hardware-error,clock,accelerator";
    let mut hasher = blake3::Hasher::new();
    hasher.update(CAPABILITY_HASH_DOMAIN);
    hasher.update(name);
    hasher.update(&[0]);
    hasher.update(schema);
    hasher.update(&[0]);
    hasher.update(&register_manifest_digest);
    match interrupt_manifest_digest {
        Some(digest) => {
            hasher.update(&[1]);
            hasher.update(&digest);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    match hardware_error_manifest_digest {
        Some(digest) => {
            hasher.update(&[1]);
            hasher.update(&digest);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    match clock_manifest_digest {
        Some(digest) => {
            hasher.update(&[1]);
            hasher.update(&digest);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    match accelerator_manifest_digest {
        Some(digest) => {
            hasher.update(&[1]);
            hasher.update(&digest);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    FaultCapabilityRowV1 {
        command_kind: FaultCommandKind::QueryTargetManifest,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        scope: architecture,
        phase_mask: FaultBoundaryPhase::NodeBoundary.bit(),
        maximum_payload_bytes: FAULT_TARGET_MANIFEST_QUERY_V1_BYTES as u32,
        maximum_pending_commands: 1,
        required_feature_bits: FAULT_CAPABILITY_FEATURE_REGISTER_MUTATION
            | interrupt_manifest_digest.map_or(0, |_digest| FAULT_CAPABILITY_FEATURE_INTERRUPT)
            | hardware_error_manifest_digest
                .map_or(0, |_digest| FAULT_CAPABILITY_FEATURE_HARDWARE_ERROR)
            | clock_manifest_digest.map_or(0, |_digest| FAULT_CAPABILITY_FEATURE_GUEST_CLOCK),
        capability_hash: *hasher.finalize().as_bytes(),
    }
}

fn register_capability_hash(
    architecture: FaultCapabilityScope,
    manifest_digest: [u8; 32],
) -> [u8; 32] {
    let name = match architecture {
        FaultCapabilityScope::X86_64 => b"qemu.register.mutate.x86_64.v1".as_slice(),
        FaultCapabilityScope::Aarch64 => b"qemu.register.mutate.aarch64.v1".as_slice(),
        _ => b"qemu.register.mutate.invalid.v1".as_slice(),
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update(CAPABILITY_HASH_DOMAIN);
    hasher.update(name);
    hasher.update(&[0]);
    hasher.update(b"crucible.node-fault-payload.v1");
    hasher.update(&[0]);
    hasher.update(&manifest_digest);
    *hasher.finalize().as_bytes()
}

fn register_command_expectation(
    payload: &[u8],
    binding_hash: [u8; 32],
    identity: &RegisterEvidenceIdentity,
) -> Result<RegisterCommandExpectation, FaultCommandBridgeError> {
    let decoded = NodeFaultPayloadV1::decode(payload)
        .map_err(|_source| FaultCommandBridgeError::RegisterEvidence)?;
    if decoded.operation == NodeFaultOperationV1::Remove {
        return Ok(RegisterCommandExpectation {
            operation: decoded.operation,
            binding_hash,
            mutation: None,
        });
    }
    let field = |tag| {
        decoded
            .fields
            .iter()
            .find(|field| field.tag == tag)
            .ok_or(FaultCommandBridgeError::RegisterEvidence)
    };
    let u32_field = |tag| {
        field(tag)?
            .value
            .as_slice()
            .try_into()
            .map(u32::from_le_bytes)
            .map_err(|_source| FaultCommandBridgeError::RegisterEvidence)
    };
    let register_identity: [u8; 32] = field(node_fault_field::T3)?
        .value
        .as_slice()
        .try_into()
        .map_err(|_source| FaultCommandBridgeError::RegisterEvidence)?;
    let row = identity
        .rows
        .iter()
        .find(|row| crucible_shmem::fault_object_id_hash_v1(&row.name) == register_identity)
        .ok_or(FaultCommandBridgeError::RegisterEvidence)?;
    let mutation_kind = match u32_field(node_fault_field::P4)? {
        1 => FaultRegisterMutationKindV1::BitFlip,
        2 => FaultRegisterMutationKindV1::Stuck,
        3 => FaultRegisterMutationKindV1::Replace,
        _ => return Err(FaultCommandBridgeError::RegisterEvidence),
    };
    Ok(RegisterCommandExpectation {
        operation: decoded.operation,
        binding_hash,
        mutation: Some(RegisterMutationExpectation {
            vcpu_index: u32_field(node_fault_field::T1)?,
            numeric_id: row.numeric_id,
            model_phase: decoded.model_phase,
            mutation_kind,
            first_bit: u32_field(node_fault_field::P2)?,
            bit_count: u32_field(node_fault_field::P3)?,
            mask: field(node_fault_field::P5)?.value.clone(),
            value: field(node_fault_field::P7)?.value.clone(),
        }),
    })
}

fn instruction_command_expectation(
    payload: &[u8],
    binding_hash: [u8; 32],
    identity: &RegisterEvidenceIdentity,
) -> Result<InstructionCommandExpectation, FaultCommandBridgeError> {
    let decoded = NodeFaultPayloadV1::decode(payload)
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    let field = |tag| {
        decoded
            .fields
            .iter()
            .find(|field| field.tag == tag)
            .ok_or(FaultCommandBridgeError::InstructionEvidence)
    };
    let u32_field = |tag| {
        field(tag)?
            .value
            .as_slice()
            .try_into()
            .map(u32::from_le_bytes)
            .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)
    };
    let selector = policy_json(&field(node_fault_field::P1)?.value, false)?;
    let selector = selector
        .as_object()
        .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
    let pc_start = json_u64(selector.get("pc_start"))?;
    let pc_length = json_u64(selector.get("pc_length"))?;
    if pc_length == 0 || pc_start.checked_add(pc_length).is_none() {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    let instruction_bytes = match selector.get("instruction_bytes") {
        Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(value)) => Some(hex_bytes(value)?),
        _ => return Err(FaultCommandBridgeError::InstructionEvidence),
    };
    if instruction_bytes
        .as_ref()
        .is_some_and(|bytes| bytes.is_empty() || bytes.len() > 32)
    {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    let opcode_class = match selector.get("opcode_class") {
        Some(serde_json::Value::Null) => None,
        value => Some(
            u32::try_from(json_u64(value)?)
                .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?,
        ),
    };
    let input_state_sha256 = match selector.get("input_state_sha256") {
        Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(value)) => Some(
            hex_bytes(value)?
                .try_into()
                .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?,
        ),
        _ => return Err(FaultCommandBridgeError::InstructionEvidence),
    };
    let vcpu_index = u32_field(node_fault_field::T1)?;
    let mutation_kind = match u32_field(node_fault_field::P2)? {
        1 => FaultInstructionMutationKindV1::ResultCorrupt,
        2 => FaultInstructionMutationKindV1::Skip,
        3 => FaultInstructionMutationKindV1::Replay,
        _ => return Err(FaultCommandBridgeError::InstructionEvidence),
    };
    let replay_total = u32_field(node_fault_field::P5)?;
    let register_mutation = if mutation_kind == FaultInstructionMutationKindV1::ResultCorrupt {
        let register_identity: [u8; 32] = field(node_fault_field::P3)?
            .value
            .as_slice()
            .try_into()
            .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
        let row = identity
            .rows
            .iter()
            .find(|row| crucible_shmem::fault_object_id_hash_v1(&row.name) == register_identity)
            .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
        let mutation = policy_json(&field(node_fault_field::P4)?.value, false)?;
        Some(result_register_expectation(vcpu_index, row, &mutation)?)
    } else {
        None
    };
    Ok(InstructionCommandExpectation {
        operation: decoded.operation,
        binding_hash,
        generation: decoded.generation,
        action_hash: decoded.action_hash,
        target_hash: decoded.target_hash,
        vcpu_index,
        model_phase: decoded.model_phase,
        pc_start,
        pc_length,
        instruction_bytes,
        opcode_class,
        input_state_sha256,
        mutation_kind,
        replay_total,
        next_replay_ordinal: 0,
        register_mutation,
    })
}

fn exception_command_expectation(
    payload: &[u8],
    binding_hash: [u8; 32],
) -> Result<ExceptionCommandExpectation, FaultCommandBridgeError> {
    let decoded = NodeFaultPayloadV1::decode(payload)
        .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)?;
    let field = |tag| {
        decoded
            .fields
            .iter()
            .find(|field| field.tag == tag)
            .ok_or(FaultCommandBridgeError::ExceptionEvidence)
    };
    if decoded.operation != NodeFaultOperationV1::Apply {
        return Err(FaultCommandBridgeError::ExceptionEvidence);
    }
    let exception = policy_json(&field(node_fault_field::P1)?.value, true)?;
    let exception = exception
        .as_object()
        .ok_or(FaultCommandBridgeError::ExceptionEvidence)?;
    let architecture = match exception
        .get("architecture")
        .and_then(|value| value.as_str())
    {
        Some("x86_64") => FaultCapabilityScope::X86_64,
        Some("aarch64") => FaultCapabilityScope::Aarch64,
        _ => return Err(FaultCommandBridgeError::ExceptionEvidence),
    };
    let fault_address = match exception.get("fault_address") {
        Some(serde_json::Value::Null) => None,
        value => {
            Some(json_u64(value).map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)?)
        }
    };
    let maskable = exception
        .get("maskable")
        .and_then(serde_json::Value::as_bool)
        .ok_or(FaultCommandBridgeError::ExceptionEvidence)?;
    let record = exception
        .get("record")
        .and_then(serde_json::Value::as_object)
        .ok_or(FaultCommandBridgeError::ExceptionEvidence)?;
    let record_kind = record
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or(FaultCommandBridgeError::ExceptionEvidence)?;
    let optional_u64 = |value: Option<&serde_json::Value>| match value {
        Some(serde_json::Value::Null) => Ok(None),
        value => json_u64(value)
            .map(Some)
            .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence),
    };
    let hardware_record = match record_kind {
        "architecture_default" if record.get("parameters").is_none() => None,
        "x86_machine_check" => {
            let parameters = record
                .get("parameters")
                .and_then(serde_json::Value::as_object)
                .ok_or(FaultCommandBridgeError::ExceptionEvidence)?;
            Some(HardwareExceptionExpectation::X86MachineCheck {
                bank: u32::try_from(
                    json_u64(parameters.get("bank"))
                        .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)?,
                )
                .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)?,
                status: json_u64(parameters.get("status"))
                    .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)?,
                global_status: json_u64(parameters.get("global_status"))
                    .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)?,
                address: optional_u64(parameters.get("address"))?,
                misc: optional_u64(parameters.get("misc"))?,
                corrected: parameters
                    .get("corrected")
                    .and_then(serde_json::Value::as_bool)
                    .ok_or(FaultCommandBridgeError::ExceptionEvidence)?,
            })
        }
        "aarch64_ras" => {
            let parameters = record
                .get("parameters")
                .and_then(serde_json::Value::as_object)
                .ok_or(FaultCommandBridgeError::ExceptionEvidence)?;
            Some(HardwareExceptionExpectation::Aarch64Ras {
                esr: json_u64(parameters.get("esr"))
                    .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)?,
                far: optional_u64(parameters.get("far"))?,
                disr: optional_u64(parameters.get("disr"))?,
                asynchronous: parameters
                    .get("asynchronous")
                    .and_then(serde_json::Value::as_bool)
                    .ok_or(FaultCommandBridgeError::ExceptionEvidence)?,
                corrected: parameters
                    .get("corrected")
                    .and_then(serde_json::Value::as_bool)
                    .ok_or(FaultCommandBridgeError::ExceptionEvidence)?,
                fatal: parameters
                    .get("fatal")
                    .and_then(serde_json::Value::as_bool)
                    .ok_or(FaultCommandBridgeError::ExceptionEvidence)?,
            })
        }
        _ => return Err(FaultCommandBridgeError::ExceptionEvidence),
    };
    let vcpu_index = field(node_fault_field::T1)?
        .value
        .as_slice()
        .try_into()
        .map(u32::from_le_bytes)
        .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)?;
    Ok(ExceptionCommandExpectation {
        binding_hash,
        generation: decoded.generation,
        action_hash: decoded.action_hash,
        target_hash: decoded.target_hash,
        architecture,
        model_phase: decoded.model_phase,
        vcpu_index,
        vector: u32::try_from(
            json_u64(exception.get("vector"))
                .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)?,
        )
        .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)?,
        syndrome: json_u64(exception.get("syndrome"))
            .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)?,
        fault_address,
        before_instruction: exception
            .get("before_instruction")
            .and_then(|value| value.as_bool())
            .ok_or(FaultCommandBridgeError::ExceptionEvidence)?,
        maskable,
        hardware_record,
    })
}

fn memory_ecc_command_expectation(
    payload: &[u8],
    binding_hash: [u8; 32],
) -> Result<MemoryEccCommandExpectation, FaultCommandBridgeError> {
    let decoded = NodeFaultPayloadV1::decode(payload)
        .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?;
    let field = |tag| {
        decoded
            .fields
            .iter()
            .find(|field| field.tag == tag)
            .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)
    };
    if decoded.operation != NodeFaultOperationV1::Apply {
        return Err(FaultCommandBridgeError::HardwareErrorEvidence);
    }
    let u32_field = |tag| {
        field(tag)?
            .value
            .as_slice()
            .try_into()
            .map(u32::from_le_bytes)
            .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)
    };
    let u64_field = |tag| {
        field(tag)?
            .value
            .as_slice()
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)
    };
    let hash_field = |tag| {
        field(tag)?
            .value
            .as_slice()
            .try_into()
            .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)
    };
    Ok(MemoryEccCommandExpectation {
        binding_hash,
        generation: decoded.generation,
        action_hash: decoded.action_hash,
        target_hash: decoded.target_hash,
        model_phase: decoded.model_phase,
        target_vcpu: u32_field(node_fault_field::P8)?,
        kind: u32_field(node_fault_field::P1)?,
        address: u64_field(node_fault_field::P2)?,
        syndrome: u64_field(node_fault_field::P3)?,
        bank: hash_field(node_fault_field::P4)?,
        channel: hash_field(node_fault_field::P5)?,
        rank: hash_field(node_fault_field::P6)?,
        visibility: policy_json(&field(node_fault_field::P7)?.value, true)?,
    })
}

fn clock_command_expectation(
    payload: &[u8],
    binding_hash: [u8; 32],
    command_kind: FaultCommandKind,
) -> Result<ClockCommandExpectation, FaultCommandBridgeError> {
    let decoded =
        NodeFaultPayloadV1::decode(payload).map_err(|_| FaultCommandBridgeError::ClockEvidence)?;
    if decoded.operation == NodeFaultOperationV1::Remove {
        return Ok(ClockCommandExpectation {
            operation: decoded.operation,
            command_kind: command_kind as u16,
            binding_hash,
            model_phase: decoded.model_phase,
            source_ids: Vec::new(),
            parameters: ClockCommandParameters::Remove,
        });
    }
    let field = |tag| {
        decoded
            .fields
            .iter()
            .find(|field| field.tag == tag)
            .ok_or(FaultCommandBridgeError::ClockEvidence)
    };
    let u32_field = |tag| {
        field(tag)?
            .value
            .as_slice()
            .try_into()
            .map(u32::from_le_bytes)
            .map_err(|_source| FaultCommandBridgeError::ClockEvidence)
    };
    let u64_field = |tag| {
        field(tag)?
            .value
            .as_slice()
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|_source| FaultCommandBridgeError::ClockEvidence)
    };
    let i64_field = |tag| {
        field(tag)?
            .value
            .as_slice()
            .try_into()
            .map(i64::from_le_bytes)
            .map_err(|_source| FaultCommandBridgeError::ClockEvidence)
    };
    let clock_policy_json = |tag| {
        let json = field(tag)?
            .value
            .strip_prefix(b"CRUCJSN1")
            .ok_or(FaultCommandBridgeError::ClockEvidence)?;
        serde_json::from_slice(json).map_err(|_source| FaultCommandBridgeError::ClockEvidence)
    };
    let tag = if command_kind == FaultCommandKind::ClockTransform {
        node_fault_field::T1
    } else {
        node_fault_field::P1
    };
    let value = decoded
        .fields
        .iter()
        .find(|field| field.tag == tag)
        .ok_or(FaultCommandBridgeError::ClockEvidence)?
        .value
        .as_slice();
    if value.is_empty() || value.len() % 32 != 0 {
        return Err(FaultCommandBridgeError::ClockEvidence);
    }
    let parameters = if command_kind == FaultCommandKind::ClockTransform {
        let ratio = field(node_fault_field::P4)?.value.as_slice();
        let numerator = i64::from_le_bytes(
            ratio[..8]
                .try_into()
                .map_err(|_source| FaultCommandBridgeError::ClockEvidence)?,
        );
        let numerator =
            u64::try_from(numerator).map_err(|_source| FaultCommandBridgeError::ClockEvidence)?;
        let kind = u32_field(node_fault_field::P2)?;
        ClockCommandParameters::Transform {
            kind,
            signed_value: i64_field(node_fault_field::P3)?,
            ratio: [
                numerator,
                u64::from_le_bytes(
                    ratio[8..16]
                        .try_into()
                        .map_err(|_source| FaultCommandBridgeError::ClockEvidence)?,
                ),
            ],
            unsigned_value: u64_field(node_fault_field::P5)?,
            process: if matches!(kind, 4..=6) {
                Some(clock_policy_json(node_fault_field::P6)?)
            } else {
                None
            },
            monotonicity: u32_field(node_fault_field::P7)?,
            overdue_policy: u32_field(node_fault_field::P8)?,
        }
    } else {
        ClockCommandParameters::SourceState {
            transition: clock_policy_json(node_fault_field::P2)?,
            synchronization: clock_policy_json(node_fault_field::P3)?,
        }
    };
    Ok(ClockCommandExpectation {
        operation: decoded.operation,
        command_kind: command_kind as u16,
        binding_hash,
        model_phase: decoded.model_phase,
        source_ids: value
            .chunks_exact(32)
            .map(|chunk| chunk.try_into())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| FaultCommandBridgeError::ClockEvidence)?,
        parameters,
    })
}

fn accelerator_command_expectation(
    payload: &[u8],
    binding_hash: [u8; 32],
    command_kind: FaultCommandKind,
) -> Result<AcceleratorCommandExpectation, FaultCommandBridgeError> {
    let decoded = NodeFaultPayloadV1::decode(payload)
        .map_err(|_| FaultCommandBridgeError::AcceleratorEvidence)?;
    let fields = decoded
        .fields
        .into_iter()
        .map(|field| (field.tag, field.value))
        .collect();
    Ok(AcceleratorCommandExpectation {
        operation: decoded.operation,
        command_kind: command_kind as u16,
        binding_hash,
        generation: decoded.generation,
        action_hash: decoded.action_hash,
        target_hash: decoded.target_hash,
        model_phase: decoded.model_phase,
        fields,
    })
}

fn result_register_expectation(
    vcpu_index: u32,
    row: &FaultRegisterCapabilityRowV1,
    mutation: &serde_json::Value,
) -> Result<RegisterMutationExpectation, FaultCommandBridgeError> {
    let root = mutation
        .as_object()
        .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
    let kind = root
        .get("kind")
        .and_then(|value| value.as_str())
        .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
    let parameters = root
        .get("parameters")
        .and_then(|value| value.as_object())
        .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
    let width_bytes = usize::try_from(row.width_bits)
        .ok()
        .and_then(|bits| bits.checked_add(7))
        .map(|bits| bits / 8)
        .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
    let (mutation_kind, mask, value) = match kind {
        "bit_flip" => (
            FaultRegisterMutationKindV1::BitFlip,
            hex_json(parameters.get("mask"))?,
            vec![0],
        ),
        "stuck" => (
            FaultRegisterMutationKindV1::Stuck,
            hex_json(parameters.get("mask"))?,
            hex_json(parameters.get("value"))?,
        ),
        "replace" => {
            let value = hex_json(parameters.get("value"))?;
            let mut mask = vec![u8::MAX; width_bytes];
            if row.width_bits % 8 != 0 {
                mask[width_bytes - 1] = (1_u8 << (row.width_bits % 8)) - 1;
            }
            (FaultRegisterMutationKindV1::Replace, mask, value)
        }
        _ => return Err(FaultCommandBridgeError::InstructionEvidence),
    };
    if mask.len() != width_bytes
        || (mutation_kind != FaultRegisterMutationKindV1::BitFlip && value.len() != width_bytes)
    {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    Ok(RegisterMutationExpectation {
        vcpu_index,
        numeric_id: row.numeric_id,
        model_phase: 12,
        mutation_kind,
        first_bit: 0,
        bit_count: row.width_bits,
        mask,
        value,
    })
}

fn policy_json(
    bytes: &[u8],
    exception: bool,
) -> Result<serde_json::Value, FaultCommandBridgeError> {
    let invalid = || {
        if exception {
            FaultCommandBridgeError::ExceptionEvidence
        } else {
            FaultCommandBridgeError::InstructionEvidence
        }
    };
    let json = bytes.strip_prefix(b"CRUCJSN1").ok_or_else(invalid)?;
    serde_json::from_slice(json).map_err(|_source| invalid())
}

fn json_u64(value: Option<&serde_json::Value>) -> Result<u64, FaultCommandBridgeError> {
    value
        .and_then(serde_json::Value::as_u64)
        .ok_or(FaultCommandBridgeError::InstructionEvidence)
}

fn hex_json(value: Option<&serde_json::Value>) -> Result<Vec<u8>, FaultCommandBridgeError> {
    value
        .and_then(serde_json::Value::as_str)
        .ok_or(FaultCommandBridgeError::InstructionEvidence)
        .and_then(hex_bytes)
}

fn hex_bytes(value: &str) -> Result<Vec<u8>, FaultCommandBridgeError> {
    if value.len() % 2 != 0 {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let nibble = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            nibble(pair[0])
                .zip(nibble(pair[1]))
                .map(|(high, low)| high << 4 | low)
                .ok_or(FaultCommandBridgeError::InstructionEvidence)
        })
        .collect()
}

fn translate_register_evidence(
    raw: &[u8],
    identity: &RegisterEvidenceIdentity,
    logical_icount_offset: u64,
    expected_raw_icount: u64,
    expected_model_phase: Option<u16>,
    expected_before: [u8; 32],
    expected_after: [u8; 32],
    expectation: &RegisterMutationExpectation,
) -> Result<Vec<u8>, FaultCommandBridgeError> {
    const HEADER: usize = 160;
    if raw.len() < HEADER
        || raw[..8] != *b"CRUCQRW1"
        || raw_u16(raw, 8)? != 1
        || raw[14..16] != [0, 0]
        || raw[156..160].iter().any(|byte| *byte != 0)
    {
        return Err(FaultCommandBridgeError::RegisterEvidence);
    }
    let architecture = FaultCapabilityScope::from_u16(raw_u16(raw, 10)?)
        .map_err(|_source| FaultCommandBridgeError::RegisterEvidence)?;
    if architecture != identity.architecture {
        return Err(FaultCommandBridgeError::RegisterEvidence);
    }
    let model_phase = raw_u16(raw, 12)?;
    if expected_model_phase.is_some_and(|expected| expected != model_phase)
        || model_phase != expectation.model_phase
        || raw_u64(raw, 56)? != expected_raw_icount
    {
        return Err(FaultCommandBridgeError::RegisterEvidence);
    }
    let before_len = usize::try_from(raw_u32(raw, 44)?)
        .map_err(|_source| FaultCommandBridgeError::RegisterEvidence)?;
    let after_len = usize::try_from(raw_u32(raw, 48)?)
        .map_err(|_source| FaultCommandBridgeError::RegisterEvidence)?;
    let mask_len = usize::try_from(raw_u32(raw, 52)?)
        .map_err(|_source| FaultCommandBridgeError::RegisterEvidence)?;
    let value_len = usize::try_from(raw_u32(raw, 152)?)
        .map_err(|_source| FaultCommandBridgeError::RegisterEvidence)?;
    if raw.len()
        != HEADER
            .checked_add(before_len)
            .and_then(|length| length.checked_add(after_len))
            .and_then(|length| length.checked_add(mask_len))
            .and_then(|length| length.checked_add(value_len))
            .ok_or(FaultCommandBridgeError::RegisterEvidence)?
    {
        return Err(FaultCommandBridgeError::RegisterEvidence);
    }
    let mutation_kind = match raw_u32(raw, 24)? {
        1 => FaultRegisterMutationKindV1::BitFlip,
        2 => FaultRegisterMutationKindV1::Stuck,
        3 => FaultRegisterMutationKindV1::Replace,
        _ => return Err(FaultCommandBridgeError::RegisterEvidence),
    };
    if mutation_kind != expectation.mutation_kind {
        return Err(FaultCommandBridgeError::RegisterEvidence);
    }
    let observed_icount = raw_u64(raw, 56)?
        .checked_add(logical_icount_offset)
        .ok_or(FaultCommandBridgeError::CoordinateOverflow)?;
    let before_start = HEADER;
    let after_start = before_start + before_len;
    let mask_start = after_start + after_len;
    let value_start = mask_start + mask_len;
    let execution_fingerprint: [u8; 32] = raw[88..120]
        .try_into()
        .map_err(|_source| FaultCommandBridgeError::RegisterEvidence)?;
    let baseline_fingerprint: [u8; 32] = raw[120..152]
        .try_into()
        .map_err(|_source| FaultCommandBridgeError::RegisterEvidence)?;
    let numeric_id = raw_u32(raw, 20)?;
    let row = identity
        .rows
        .iter()
        .find(|row| row.numeric_id == numeric_id)
        .ok_or(FaultCommandBridgeError::RegisterEvidence)?;
    let expected_width = usize::try_from(row.width_bits)
        .ok()
        .and_then(|bits| bits.checked_add(7))
        .map(|bits| bits / 8)
        .ok_or(FaultCommandBridgeError::RegisterEvidence)?;
    let declared_side_effects = raw_u32(raw, 28)?;
    let first_bit = raw_u32(raw, 36)?;
    let bit_count = raw_u32(raw, 40)?;
    let mutation_bytes = usize::try_from(bit_count)
        .ok()
        .and_then(|bits| bits.checked_add(7))
        .map(|bits| bits / 8)
        .ok_or(FaultCommandBridgeError::RegisterEvidence)?;
    if before_len != expected_width
        || after_len != expected_width
        || mask_len != mutation_bytes
        || value_len
            != if mutation_kind == FaultRegisterMutationKindV1::BitFlip {
                1
            } else {
                mutation_bytes
            }
        || declared_side_effects != row.side_effects
        || model_phase == 0
        || model_phase > 64
        || row.model_phase_mask & (1_u64 << (model_phase - 1)) == 0
        || (expected_model_phase.is_none()
            && row.capabilities & FAULT_REGISTER_CAPABILITY_IMPULSE == 0)
        || first_bit
            .checked_add(bit_count)
            .is_none_or(|end| end > row.width_bits)
    {
        return Err(FaultCommandBridgeError::RegisterEvidence);
    }
    if raw_u32(raw, 16)? != expectation.vcpu_index
        || raw_u64(raw, 64)? != u64::from(expectation.vcpu_index)
        || numeric_id != expectation.numeric_id
        || first_bit != expectation.first_bit
        || bit_count != expectation.bit_count
        || raw[mask_start..value_start] != expectation.mask
        || raw[value_start..] != expectation.value
        || execution_fingerprint == [0; 32]
        || baseline_fingerprint == [0; 32]
        || ((baseline_fingerprint != execution_fingerprint)
            != (raw[before_start..after_start] != raw[after_start..mask_start]))
        || (expected_model_phase.is_none() && baseline_fingerprint == execution_fingerprint)
    {
        return Err(FaultCommandBridgeError::RegisterEvidence);
    }
    let raw_mask = &raw[mask_start..value_start];
    for bit in 0..bit_count {
        if raw_mask[bit as usize / 8] & (1_u8 << (bit % 8)) != 0
            && row.writable_mask[(first_bit + bit) as usize / 8] & (1_u8 << ((first_bit + bit) % 8))
                == 0
        {
            return Err(FaultCommandBridgeError::RegisterEvidence);
        }
    }
    let evidence = FaultRegisterMutationEvidenceV1 {
        architecture,
        model_phase,
        vcpu_index: raw_u32(raw, 16)?,
        numeric_id,
        mutation_kind,
        declared_side_effects,
        performed_side_effects: raw_u32(raw, 32)?,
        first_bit,
        bit_count,
        observed_icount,
        rr_current_vcpu: raw_u64(raw, 64)?,
        rr_cursor_position: raw_u64(raw, 72)?,
        rr_switch_quantum: raw_u64(raw, 80)?,
        manifest_digest: identity.manifest_digest,
        cpu_model_digest: identity.cpu_model_digest,
        before_sha256: expected_before,
        after_sha256: expected_after,
        execution_fingerprint_sha256: execution_fingerprint,
        before: raw[before_start..after_start].to_vec(),
        after: raw[after_start..mask_start].to_vec(),
        mask: raw[mask_start..value_start].to_vec(),
        value: raw[value_start..].to_vec(),
    };
    evidence
        .encode()
        .map_err(|_source| FaultCommandBridgeError::RegisterEvidence)
}

/// Validates a generic terminal record that replaced instruction evidence.
fn translate_terminal_instruction_evidence(
    raw: &[u8],
    event: &QemuFaultEvent,
    expectation: &InstructionCommandExpectation,
) -> Result<Vec<u8>, FaultCommandBridgeError> {
    let evidence = FaultTerminalEvidenceV1::decode(raw)
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    if event.outcome != FaultEventOutcomeV1::Error as u16
        || event.binding_hash != expectation.binding_hash
        || event.generation != expectation.generation
        || event.action_hash != expectation.action_hash
        || event.target_hash != expectation.target_hash
        || event.model_phase != expectation.model_phase
        || event.target_kind != NodeFaultTargetKindV1::Vcpu as u16
        || evidence.attempted_payload_sha256 != event.opportunity_hash
    {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    Ok(raw.to_vec())
}

fn translate_instruction_evidence(
    raw: &[u8],
    identity: &InstructionEvidenceIdentity,
    register_identity: &RegisterEvidenceIdentity,
    logical_icount_offset: u64,
    event: &QemuFaultEvent,
    expectation: &InstructionCommandExpectation,
) -> Result<Vec<u8>, FaultCommandBridgeError> {
    const HEADER: usize = 608;
    let invalid = |_| FaultCommandBridgeError::InstructionEvidence;
    if raw.len() < HEADER
        || raw[..8] != *b"CRUCINS1"
        || raw_u16(raw, 8).map_err(invalid)? != 3
        || raw[600..608].iter().any(|byte| *byte != 0)
        || event.binding_hash != expectation.binding_hash
        || event.generation != expectation.generation
        || event.action_hash != expectation.action_hash
        || event.target_hash != expectation.target_hash
        || event.model_phase != expectation.model_phase
        || event.target_kind != NodeFaultTargetKindV1::Vcpu as u16
        || raw_u64(raw, 48).map_err(invalid)? != event.observed_icount
        || raw[96..128] != event.before_hash
        || raw[128..160] != event.after_hash
        || raw[192..224] != identity.manifest_sha256
    {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    let raw_digest: [u8; 32] = sha2::Sha256::digest(raw).into();
    if raw_digest != event.opportunity_hash {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    let before_cpu: [u8; 32] = raw[416..448]
        .try_into()
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    let after_cpu: [u8; 32] = raw[448..480]
        .try_into()
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    let before_ram: [u8; 32] = raw[288..320]
        .try_into()
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    let after_ram: [u8; 32] = raw[320..352]
        .try_into()
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    let before_device: [u8; 32] = raw[352..384]
        .try_into()
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    let after_device: [u8; 32] = raw[384..416]
        .try_into()
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    if instruction_system_digest(
        before_cpu,
        before_ram,
        before_device,
        raw_u64(raw, 480).map_err(invalid)?,
        raw_u64(raw, 496).map_err(invalid)?,
    ) != event.before_hash
        || instruction_system_digest(
            after_cpu,
            after_ram,
            after_device,
            raw_u64(raw, 488).map_err(invalid)?,
            raw_u64(raw, 504).map_err(invalid)?,
        ) != event.after_hash
    {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    let architecture = FaultCapabilityScope::from_u16(raw_u16(raw, 10).map_err(invalid)?)
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    if architecture != identity.architecture || architecture != register_identity.architecture {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    let mutation_kind = match raw_u32(raw, 12).map_err(invalid)? {
        1 => FaultInstructionMutationKindV1::ResultCorrupt,
        2 => FaultInstructionMutationKindV1::Skip,
        3 => FaultInstructionMutationKindV1::Replay,
        _ => return Err(FaultCommandBridgeError::InstructionEvidence),
    };
    let outcome = match event.outcome {
        value if value == FaultEventOutcomeV1::Applied as u16 => {
            FaultInstructionEvidenceOutcomeV1::Applied
        }
        value if value == FaultEventOutcomeV1::Suppressed as u16 => {
            FaultInstructionEvidenceOutcomeV1::Suppressed
        }
        value if value == FaultEventOutcomeV1::Error as u16 => {
            FaultInstructionEvidenceOutcomeV1::Error
        }
        _ => return Err(FaultCommandBridgeError::InstructionEvidence),
    };
    if outcome == FaultInstructionEvidenceOutcomeV1::Applied {
        if expectation
            .input_state_sha256
            .is_some_and(|expected| raw[568..600] != expected)
        {
            return Err(FaultCommandBridgeError::InstructionEvidence);
        }
    } else if outcome == FaultInstructionEvidenceOutcomeV1::Suppressed
        && (expectation.input_state_sha256.is_none()
            || raw[96..128] != raw[128..160]
            || expectation.input_state_sha256 == raw[568..600].try_into().ok())
    {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    let instruction_len = usize::try_from(raw_u32(raw, 56).map_err(invalid)?)
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    let detail_len = usize::try_from(raw_u32(raw, 60).map_err(invalid)?)
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    let expected_len = HEADER
        .checked_add(instruction_len)
        .and_then(|length| length.checked_add(detail_len))
        .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
    let destination_count = usize::try_from(raw_u32(raw, 164).map_err(invalid)?)
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    let page_count = usize::try_from(raw_u32(raw, 528).map_err(invalid)?)
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    if raw.len() != expected_len
        || destination_count > 4
        || !(1..=2).contains(&page_count)
        || raw_u32(raw, 160).map_err(invalid)? != expectation.vcpu_index
        || mutation_kind != expectation.mutation_kind
        || raw_u32(raw, 20).map_err(invalid)? != expectation.replay_total
        || raw_u32(raw, 532).map_err(invalid)?
            != u32::from(expectation.input_state_sha256.is_some())
        || raw[536..568] != expectation.input_state_sha256.unwrap_or([0; 32])
    {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    let pc = raw_u64(raw, 32).map_err(invalid)?;
    if pc < expectation.pc_start
        || pc >= expectation.pc_start + expectation.pc_length
        || expectation
            .instruction_bytes
            .as_ref()
            .is_some_and(|expected| expected.as_slice() != &raw[HEADER..HEADER + instruction_len])
        || expectation
            .opcode_class
            .is_some_and(|expected| expected != raw_u32(raw, 24).unwrap_or(0))
    {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    let raw_detail = &raw[HEADER + instruction_len..];
    let detail = match (outcome, &expectation.register_mutation, mutation_kind) {
        (
            FaultInstructionEvidenceOutcomeV1::Applied,
            Some(register),
            FaultInstructionMutationKindV1::ResultCorrupt,
        ) => {
            let translated = translate_register_evidence(
                raw_detail,
                register_identity,
                logical_icount_offset,
                event.observed_icount,
                Some(12),
                event.before_hash,
                event.after_hash,
                register,
            )?;
            if !(0..destination_count)
                .any(|index| raw_u32(raw, 168 + index * 4).ok() == Some(register.numeric_id))
            {
                return Err(FaultCommandBridgeError::InstructionEvidence);
            }
            translated
        }
        (
            FaultInstructionEvidenceOutcomeV1::Applied,
            None,
            FaultInstructionMutationKindV1::Replay,
        ) if raw_u32(raw, 24).map_err(invalid)? == 0x0100_0008 => {
            let transcript = FaultInstructionPortIoEvidenceV1::decode(raw_detail)
                .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
            if transcript.entries.iter().any(|entry| !entry.completed) {
                return Err(FaultCommandBridgeError::InstructionEvidence);
            }
            transcript
                .encode()
                .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?
        }
        (
            FaultInstructionEvidenceOutcomeV1::Applied,
            None,
            FaultInstructionMutationKindV1::Skip | FaultInstructionMutationKindV1::Replay,
        ) if raw_detail.is_empty() => Vec::new(),
        (FaultInstructionEvidenceOutcomeV1::Suppressed, _, _) if raw_detail.is_empty() => {
            Vec::new()
        }
        (FaultInstructionEvidenceOutcomeV1::Error, _, _) if raw_detail.len() <= 32 => {
            raw_detail.to_vec()
        }
        _ => return Err(FaultCommandBridgeError::InstructionEvidence),
    };
    let observed_icount = event
        .observed_icount
        .checked_add(logical_icount_offset)
        .ok_or(FaultCommandBridgeError::CoordinateOverflow)?;
    let evidence = FaultInstructionEvidenceV1 {
        architecture,
        mutation_kind,
        outcome,
        replay_ordinal: raw_u32(raw, 16).map_err(invalid)?,
        replay_total: raw_u32(raw, 20).map_err(invalid)?,
        opcode_class: raw_u32(raw, 24).map_err(invalid)?,
        flags: raw_u32(raw, 28).map_err(invalid)?,
        pc,
        physical_address: raw_u64(raw, 40).map_err(invalid)?,
        observed_icount,
        vcpu_index: raw_u32(raw, 160).map_err(invalid)?,
        destinations: (0..destination_count)
            .map(|index| raw_u32(raw, 168 + index * 4).map_err(invalid))
            .collect::<Result<_, _>>()?,
        instruction_sha256: raw[64..96]
            .try_into()
            .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?,
        before_state_sha256: event.before_hash,
        after_state_sha256: event.after_hash,
        manifest_sha256: identity.manifest_sha256,
        before_cpu_sha256: before_cpu,
        after_cpu_sha256: after_cpu,
        input_state_sha256: expectation.input_state_sha256,
        matched_input_state_sha256: raw[568..600]
            .try_into()
            .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?,
        code_page_bases: (0..page_count)
            .map(|index| raw_u64(raw, 512 + index * 8).map_err(invalid))
            .collect::<Result<_, _>>()?,
        code_page_sha256: (0..page_count)
            .map(|index| {
                raw.get(224 + index * 32..256 + index * 32)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(FaultCommandBridgeError::InstructionEvidence)
            })
            .collect::<Result<_, _>>()?,
        before_ram_sha256: before_ram,
        after_ram_sha256: after_ram,
        before_device_sha256: before_device,
        after_device_sha256: after_device,
        before_ram_bytes: raw_u64(raw, 480).map_err(invalid)?,
        after_ram_bytes: raw_u64(raw, 488).map_err(invalid)?,
        before_device_bytes: raw_u64(raw, 496).map_err(invalid)?,
        after_device_bytes: raw_u64(raw, 504).map_err(invalid)?,
        instruction_bytes: raw[HEADER..HEADER + instruction_len].to_vec(),
        detail,
    };
    evidence
        .encode()
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)
}

fn translate_exception_evidence(
    raw: &[u8],
    identity: &InstructionEvidenceIdentity,
    logical_icount_offset: u64,
    event: &QemuFaultEvent,
    expectation: &ExceptionCommandExpectation,
) -> Result<Vec<u8>, FaultCommandBridgeError> {
    let invalid = |_| FaultCommandBridgeError::ExceptionEvidence;
    if raw.len() != 192
        || raw[..8] != *b"CRUCEXC1"
        || raw_u16(raw, 8).map_err(invalid)? != 2
        || event.binding_hash != expectation.binding_hash
        || event.generation != expectation.generation
        || event.action_hash != expectation.action_hash
        || event.target_hash != expectation.target_hash
        || event.model_phase != expectation.model_phase
        || event.target_kind != NodeFaultTargetKindV1::Vcpu as u16
        || event.outcome != FaultEventOutcomeV1::Applied as u16
        || raw_u64(raw, 56).map_err(invalid)? != event.observed_icount
        || raw[96..128] != event.before_hash
        || raw[128..160] != event.after_hash
        || raw[14..16].iter().any(|byte| *byte != 0)
        || raw[52..56].iter().any(|byte| *byte != 0)
        || raw[77..80].iter().any(|byte| *byte != 0)
        || raw[160..192].iter().any(|byte| *byte != 0)
    {
        return Err(FaultCommandBridgeError::ExceptionEvidence);
    }
    let raw_digest: [u8; 32] = sha2::Sha256::digest(raw).into();
    let architecture = FaultCapabilityScope::from_u16(raw_u16(raw, 10).map_err(invalid)?)
        .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)?;
    let has_address = raw[48] == 1;
    if raw_digest != event.opportunity_hash
        || architecture != identity.architecture
        || architecture != expectation.architecture
        || raw_u16(raw, 12).map_err(invalid)? != expectation.model_phase
        || raw_u32(raw, 16).map_err(invalid)? != expectation.vcpu_index
        || raw_u32(raw, 20).map_err(invalid)? != expectation.vector
        || raw_u64(raw, 24).map_err(invalid)? != expectation.syndrome
        || has_address != expectation.fault_address.is_some()
        || raw_u64(raw, 32).map_err(invalid)? != expectation.fault_address.unwrap_or(0)
        || raw[49] != u8::from(expectation.before_instruction)
        || raw[50] != u8::from(expectation.maskable)
        || raw[51] != 1
        || expectation.hardware_record.is_some()
        || raw_u32(raw, 72).map_err(invalid)? != expectation.vector
        || raw[76] != u8::from(has_address)
        || raw_u64(raw, 80).map_err(invalid)? != expectation.syndrome
        || raw_u64(raw, 88).map_err(invalid)? != expectation.fault_address.unwrap_or(0)
    {
        return Err(FaultCommandBridgeError::ExceptionEvidence);
    }
    let evidence = FaultExceptionEvidenceV1 {
        architecture,
        model_phase: expectation.model_phase,
        vcpu_index: expectation.vcpu_index,
        vector: expectation.vector,
        syndrome: expectation.syndrome,
        fault_address: expectation.fault_address,
        before_instruction: expectation.before_instruction,
        command_icount: raw_u64(raw, 40)
            .map_err(invalid)?
            .checked_add(logical_icount_offset)
            .ok_or(FaultCommandBridgeError::CoordinateOverflow)?,
        delivered_icount: event
            .observed_icount
            .checked_add(logical_icount_offset)
            .ok_or(FaultCommandBridgeError::CoordinateOverflow)?,
        entry_pc: raw_u64(raw, 64).map_err(invalid)?,
        before_sha256: event.before_hash,
        after_sha256: event.after_hash,
    };
    evidence
        .encode()
        .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)
}

fn translate_hardware_exception_evidence(
    raw: &[u8],
    manifest_payload: &[u8],
    event: &QemuFaultEvent,
    expectation: &ExceptionCommandExpectation,
) -> Result<Vec<u8>, FaultCommandBridgeError> {
    const BEFORE_STATE: usize = 392;
    const AFTER_STATE: usize = 520;
    let invalid = |_| FaultCommandBridgeError::HardwareErrorEvidence;
    if raw.len() != 744
        || raw[..8] != *b"CRUCEXC1"
        || raw_u16(raw, 8).map_err(invalid)? != 2
        || raw[51] != 2
        || raw[14..16].iter().any(|byte| *byte != 0)
        || raw[52..56].iter().any(|byte| *byte != 0)
        || raw[77..80].iter().any(|byte| *byte != 0)
        || raw[205..256].iter().any(|byte| *byte != 0)
        || raw[388..392].iter().any(|byte| *byte != 0)
        || raw[BEFORE_STATE..BEFORE_STATE + 8] != *b"CRUCHCS1"
        || raw[AFTER_STATE..AFTER_STATE + 8] != *b"CRUCHCS1"
        || event.binding_hash != expectation.binding_hash
        || event.generation != expectation.generation
        || event.action_hash != expectation.action_hash
        || event.target_hash != expectation.target_hash
        || event.model_phase != expectation.model_phase
        || event.target_kind != NodeFaultTargetKindV1::Vcpu as u16
        || event.outcome != FaultEventOutcomeV1::Applied as u16
        || raw_u64(raw, 56).map_err(invalid)? != event.observed_icount
        || raw[96..128] != event.before_hash
        || raw[128..160] != event.after_hash
    {
        return Err(FaultCommandBridgeError::HardwareErrorEvidence);
    }
    let raw_digest: [u8; 32] = sha2::Sha256::digest(raw).into();
    if raw_digest != event.opportunity_hash {
        return Err(FaultCommandBridgeError::HardwareErrorEvidence);
    }
    let manifest = FaultHardwareErrorCapabilityManifestV1::decode(manifest_payload)
        .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?;
    let row_index = usize::try_from(raw_u32(raw, 384).map_err(invalid)?)
        .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?;
    let row = manifest
        .rows
        .get(row_index)
        .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?;
    if raw[256..288] != crucible_shmem::fault_object_id_hash_v1(&row.id)
        || raw[288..320] != crucible_shmem::fault_object_id_hash_v1(&row.bank)
        || raw[320..352] != crucible_shmem::fault_object_id_hash_v1(&row.channel)
        || raw[352..384] != crucible_shmem::fault_object_id_hash_v1(&row.rank)
        || &raw[648..680] != sha2::Sha256::digest(manifest_payload).as_slice()
        || raw[680..712] != crucible_shmem::fault_object_id_hash_v1(&row.firmware)
        || raw[712..744] != crucible_shmem::fault_object_id_hash_v1(&row.state)
        || manifest.architecture != expectation.architecture
        || raw_u16(raw, 10).map_err(invalid)? != expectation.architecture as u16
        || raw_u16(raw, 12).map_err(invalid)? != expectation.model_phase
        || raw_u32(raw, 16).map_err(invalid)? != expectation.vcpu_index
        || raw_u32(raw, 20).map_err(invalid)? != expectation.vector
        || raw_u64(raw, 24).map_err(invalid)? != expectation.syndrome
        || raw_u64(raw, 32).map_err(invalid)? != expectation.fault_address.unwrap_or(0)
        || raw[48] != u8::from(expectation.fault_address.is_some())
        || raw[49] != u8::from(expectation.before_instruction)
        || raw_u32(raw, BEFORE_STATE + 8).map_err(invalid)? != expectation.architecture as u32
        || raw_u32(raw, AFTER_STATE + 8).map_err(invalid)? != expectation.architecture as u32
    {
        return Err(FaultCommandBridgeError::HardwareErrorEvidence);
    }
    let record = raw_u16(raw, 160).map_err(invalid)?;
    match (&row.record_kind, &expectation.hardware_record) {
        (
            FaultHardwareErrorRecordKindV1::X86MachineCheck,
            Some(HardwareExceptionExpectation::X86MachineCheck {
                bank: expected_bank,
                status: expected_status,
                global_status: expected_global_status,
                address: expected_address,
                misc: expected_misc,
                corrected: expected_corrected,
            }),
        ) if record == 2 => {
            let bank = raw_u32(raw, 164).map_err(invalid)?;
            let status = raw_u64(raw, 168).map_err(invalid)?;
            let before_status = raw_u64(raw, BEFORE_STATE + 40).map_err(invalid)?;
            let preserves_uncorrectable = raw[200] == 1
                && before_status & ((1_u64 << 63) | (1_u64 << 61))
                    == ((1_u64 << 63) | (1_u64 << 61));
            let merged_status = if preserves_uncorrectable {
                before_status | (1_u64 << 62)
            } else if before_status & (1_u64 << 63) != 0 {
                status | (1_u64 << 62)
            } else {
                status
            };
            if bank != *expected_bank
                || status != *expected_status
                || raw_u64(raw, 176).map_err(invalid)? != *expected_global_status
                || raw_u64(raw, 184).map_err(invalid)? != expected_address.unwrap_or(0)
                || raw_u64(raw, 192).map_err(invalid)? != expected_misc.unwrap_or(0)
                || raw[200] != u8::from(*expected_corrected)
                || raw[201] != u8::from(expected_address.is_some())
                || raw[202] != u8::from(expected_misc.is_some())
                || raw[203] != 0
                || raw[204] != 0
                || raw[50] != u8::from(expectation.maskable)
                || (*expected_corrected
                    && (raw_u64(raw, 64).map_err(invalid)? != 0
                        || raw_u32(raw, 72).map_err(invalid)? != 0
                        || raw[76] != 0
                        || raw_u64(raw, 80).map_err(invalid)? != 0
                        || raw_u64(raw, 88).map_err(invalid)? != 0))
                || (!*expected_corrected
                    && (raw_u32(raw, 72).map_err(invalid)? != expectation.vector
                        || raw[76] != u8::from(expectation.fault_address.is_some())
                        || raw_u64(raw, 80).map_err(invalid)? != expectation.syndrome
                        || raw_u64(raw, 88).map_err(invalid)?
                            != expectation.fault_address.unwrap_or(0)))
                || bank < row.bank_number
                || bank >= row.bank_number + row.bank_count
                || status & row.status_required != row.status_required
                || status & !row.status_allowed != 0
                || raw_u32(raw, BEFORE_STATE + 16).map_err(invalid)? != bank
                || raw_u32(raw, AFTER_STATE + 16).map_err(invalid)? != bank
                || raw_u64(raw, AFTER_STATE + 40).map_err(invalid)? != merged_status
                || (!preserves_uncorrectable
                    && raw_u64(raw, AFTER_STATE + 48).map_err(invalid)?
                        != raw_u64(raw, 184).map_err(invalid)?)
                || (!preserves_uncorrectable
                    && raw_u64(raw, AFTER_STATE + 56).map_err(invalid)?
                        != raw_u64(raw, 192).map_err(invalid)?)
                || raw_u64(raw, AFTER_STATE + 64).map_err(invalid)?
                    != raw_u64(raw, 176).map_err(invalid)?
            {
                return Err(FaultCommandBridgeError::HardwareErrorEvidence);
            }
        }
        (
            FaultHardwareErrorRecordKindV1::Aarch64Ras,
            Some(HardwareExceptionExpectation::Aarch64Ras {
                esr: expected_esr,
                far: expected_far,
                disr: expected_disr,
                asynchronous: expected_asynchronous,
                corrected: expected_corrected,
                fatal: expected_fatal,
            }),
        ) if record == 3 => {
            let asynchronous = raw[200] == 1;
            if raw_u64(raw, 168).map_err(invalid)? != *expected_esr
                || raw_u64(raw, 176).map_err(invalid)? != expected_far.unwrap_or(0)
                || raw_u64(raw, 184).map_err(invalid)? != expected_disr.unwrap_or(0)
                || raw[200] != u8::from(*expected_asynchronous)
                || raw[201] != u8::from(*expected_corrected)
                || raw[202] != u8::from(expected_far.is_some())
                || raw[203] != u8::from(expected_disr.is_some())
                || raw[204] != u8::from(*expected_fatal)
                || *expected_fatal != (row.error_class == FaultHardwareErrorClassV1::Fatal)
                || raw[50] != u8::from(row.maskable)
                || (*expected_corrected
                    && (raw_u64(raw, 64).map_err(invalid)? != 0
                        || raw_u32(raw, 72).map_err(invalid)? != 0
                        || raw[76] != 0
                        || raw_u64(raw, 80).map_err(invalid)? != 0
                        || raw_u64(raw, 88).map_err(invalid)? != 0))
                || (!*expected_corrected
                    && (raw_u32(raw, 72).map_err(invalid)? != expectation.vector
                        || raw[76] != u8::from(expectation.fault_address.is_some())
                        || raw_u64(raw, 80).map_err(invalid)? != expectation.syndrome
                        || raw_u64(raw, 88).map_err(invalid)?
                            != expectation.fault_address.unwrap_or(0)))
                || (asynchronous
                    && raw_u64(raw, AFTER_STATE + 104).map_err(invalid)?
                        != raw_u64(raw, 184).map_err(invalid)?)
                || (!asynchronous
                    && (raw_u64(raw, AFTER_STATE + 72).map_err(invalid)?
                        != raw_u64(raw, 168).map_err(invalid)?
                        || raw_u64(raw, AFTER_STATE + 80).map_err(invalid)?
                            != raw_u64(raw, 176).map_err(invalid)?))
            {
                return Err(FaultCommandBridgeError::HardwareErrorEvidence);
            }
        }
        _ => return Err(FaultCommandBridgeError::HardwareErrorEvidence),
    }
    Ok(raw.to_vec())
}

fn translate_hardware_ecc_evidence(
    raw: &[u8],
    manifest_payload: &[u8],
    event: &QemuFaultEvent,
    expectation: &MemoryEccCommandExpectation,
) -> Result<Vec<u8>, FaultCommandBridgeError> {
    const BEFORE_CPU: usize = 416;
    const QUEUED_CPU: usize = 544;
    const AFTER_CPU: usize = 672;
    const BEFORE_GHES: usize = 800;
    const QUEUED_GHES: usize = 992;
    const AFTER_GHES: usize = 1184;
    let invalid = |_| FaultCommandBridgeError::HardwareErrorEvidence;
    if raw.len() != 1376
        || raw[..8] != *b"CRUCHWE1"
        || raw_u16(raw, 8).map_err(invalid)? != 1
        || event.command_kind != FaultCommandKind::MemoryEccEvent as u16
        || event.outcome != FaultEventOutcomeV1::Applied as u16
        || event.binding_hash != expectation.binding_hash
        || event.generation != expectation.generation
        || event.action_hash != expectation.action_hash
        || event.target_hash != expectation.target_hash
        || event.model_phase != expectation.model_phase
        || event.target_kind != NodeFaultTargetKindV1::Memory as u16
        || raw_u64(raw, 16).map_err(invalid)? != event.observed_icount
        || raw_u64(raw, 40).map_err(invalid)? != event.rule_command_sequence
        || raw_u64(raw, 24).map_err(invalid)? != expectation.address
        || raw_u64(raw, 32).map_err(invalid)? != expectation.syndrome
        || raw_u32(raw, 52).map_err(invalid)? != expectation.target_vcpu
        || sha2::Sha256::digest(raw).as_slice() != event.opportunity_hash
    {
        return Err(FaultCommandBridgeError::HardwareErrorEvidence);
    }
    let manifest = FaultHardwareErrorCapabilityManifestV1::decode(manifest_payload)
        .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?;
    let row_index = usize::try_from(raw_u32(raw, 12).map_err(invalid)?)
        .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?;
    let row = manifest
        .rows
        .get(row_index)
        .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?;
    if row.record_kind != FaultHardwareErrorRecordKindV1::MemoryEcc
        || raw_u16(raw, 10).map_err(invalid)? != manifest.architecture as u16
        || raw[64..96] != crucible_shmem::fault_object_id_hash_v1(&row.id)
        || raw[96..128] != crucible_shmem::fault_object_id_hash_v1(&row.bank)
        || raw[128..160] != crucible_shmem::fault_object_id_hash_v1(&row.channel)
        || raw[160..192] != crucible_shmem::fault_object_id_hash_v1(&row.rank)
        || &raw[320..352] != sha2::Sha256::digest(manifest_payload).as_slice()
        || raw[352..384] != crucible_shmem::fault_object_id_hash_v1(&row.firmware)
        || raw[384..416] != crucible_shmem::fault_object_id_hash_v1(&row.state)
        || raw[96..128] != expectation.bank
        || raw[128..160] != expectation.channel
        || raw[160..192] != expectation.rank
        || raw[49..52].iter().any(|byte| *byte != 0)
        || raw[56..64].iter().any(|byte| *byte != 0)
        || raw[288..320].iter().any(|byte| *byte != 0)
    {
        return Err(FaultCommandBridgeError::HardwareErrorEvidence);
    }
    let address = raw_u64(raw, 24).map_err(invalid)?;
    let visibility = expectation
        .visibility
        .as_object()
        .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?;
    let visibility_kind = visibility
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?;
    if (expectation.kind == 1
        && (visibility.len() != 1 || visibility_kind != "telemetry_only" || raw[48] != 1))
        || (expectation.kind == 2
            && (visibility.len() != 2 || visibility_kind != "exception" || raw[48] != 2))
        || !matches!(expectation.kind, 1 | 2)
        || row.corrected != (expectation.kind == 1)
    {
        return Err(FaultCommandBridgeError::HardwareErrorEvidence);
    }
    if expectation.kind == 2 {
        let exception = visibility
            .get("parameters")
            .and_then(serde_json::Value::as_object)
            .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?;
        let record = exception
            .get("record")
            .and_then(serde_json::Value::as_object)
            .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?;
        let record_parameters = record
            .get("parameters")
            .and_then(serde_json::Value::as_object)
            .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?;
        let architecture = exception
            .get("architecture")
            .and_then(serde_json::Value::as_str)
            .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?;
        let record_kind = record
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?;
        let vector = u32::try_from(
            json_u64(exception.get("vector"))
                .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?,
        )
        .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?;
        let exception_syndrome = json_u64(exception.get("syndrome"))
            .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?;
        let fault_address = json_u64(exception.get("fault_address"))
            .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?;
        let before_instruction = exception
            .get("before_instruction")
            .and_then(serde_json::Value::as_bool)
            .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?;
        let maskable = exception
            .get("maskable")
            .and_then(serde_json::Value::as_bool)
            .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?;
        let flags = raw_u32(raw, 256).map_err(invalid)?;
        if exception.len() != 7
            || record.len() != 2
            || raw_u32(raw, 196).map_err(invalid)? != vector
            || raw_u64(raw, 200).map_err(invalid)? != exception_syndrome
            || raw_u64(raw, 208).map_err(invalid)? != fault_address
            || flags & 1 == 0
            || ((flags >> 1) & 1) != u32::from(before_instruction)
            || ((flags >> 2) & 1) != u32::from(maskable)
        {
            return Err(FaultCommandBridgeError::HardwareErrorEvidence);
        }
        match (architecture, record_kind) {
            ("x86_64", "x86_machine_check") => {
                let address = json_u64(record_parameters.get("address"))
                    .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?;
                let misc = match record_parameters.get("misc") {
                    Some(serde_json::Value::Null) => None,
                    value => Some(
                        json_u64(value)
                            .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?,
                    ),
                };
                if record_parameters.len() != 7
                    || raw_u16(raw, 192).map_err(invalid)? != 2
                    || raw_u32(raw, 216).map_err(invalid)?
                        != u32::try_from(
                            json_u64(record_parameters.get("bank")).map_err(|_source| {
                                FaultCommandBridgeError::HardwareErrorEvidence
                            })?,
                        )
                        .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?
                    || raw_u64(raw, 224).map_err(invalid)?
                        != json_u64(record_parameters.get("status"))
                            .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?
                    || raw_u64(raw, 232).map_err(invalid)?
                        != json_u64(record_parameters.get("global_status"))
                            .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?
                    || raw_u64(raw, 240).map_err(invalid)? != address
                    || raw_u64(raw, 248).map_err(invalid)? != misc.unwrap_or(0)
                    || ((flags >> 3) & 1)
                        != u32::from(
                            record_parameters
                                .get("corrected")
                                .and_then(serde_json::Value::as_bool)
                                .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?,
                        )
                    || ((flags >> 4) & 1) != 1
                    || ((flags >> 5) & 1) != u32::from(misc.is_some())
                    || flags & !0x3f != 0
                {
                    return Err(FaultCommandBridgeError::HardwareErrorEvidence);
                }
            }
            ("aarch64", "aarch64_ras") => {
                let optional = |name| match record_parameters.get(name) {
                    Some(serde_json::Value::Null) => Ok(None),
                    value => json_u64(value)
                        .map(Some)
                        .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence),
                };
                let far = optional("far")?;
                let disr = optional("disr")?;
                if record_parameters.len() != 6
                    || raw_u16(raw, 192).map_err(invalid)? != 3
                    || raw_u64(raw, 264).map_err(invalid)?
                        != json_u64(record_parameters.get("esr"))
                            .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?
                    || raw_u64(raw, 272).map_err(invalid)? != far.unwrap_or(0)
                    || raw_u64(raw, 280).map_err(invalid)? != disr.unwrap_or(0)
                    || ((flags >> 3) & 1)
                        != u32::from(
                            record_parameters
                                .get("asynchronous")
                                .and_then(serde_json::Value::as_bool)
                                .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?,
                        )
                    || ((flags >> 4) & 1)
                        != u32::from(
                            record_parameters
                                .get("corrected")
                                .and_then(serde_json::Value::as_bool)
                                .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?,
                        )
                    || ((flags >> 5) & 1)
                        != u32::from(
                            record_parameters
                                .get("fatal")
                                .and_then(serde_json::Value::as_bool)
                                .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?,
                        )
                    || ((flags >> 6) & 1) != u32::from(far.is_some())
                    || ((flags >> 7) & 1) != u32::from(disr.is_some())
                    || flags & !0xff != 0
                {
                    return Err(FaultCommandBridgeError::HardwareErrorEvidence);
                }
            }
            _ => return Err(FaultCommandBridgeError::HardwareErrorEvidence),
        }
    } else if raw_u16(raw, 192).map_err(invalid)? != 0
        && row.mechanism == FaultHardwareErrorMechanismV1::AcpiGhes
    {
        return Err(FaultCommandBridgeError::HardwareErrorEvidence);
    }
    match row.mechanism {
        FaultHardwareErrorMechanismV1::X86Mca => {
            for offset in [BEFORE_CPU, QUEUED_CPU, AFTER_CPU] {
                if raw[offset..offset + 8] != *b"CRUCHCS1"
                    || raw_u32(raw, offset + 8).map_err(invalid)?
                        != FaultCapabilityScope::X86_64 as u32
                    || raw_u32(raw, offset + 16).map_err(invalid)? != row.bank_number
                {
                    return Err(FaultCommandBridgeError::HardwareErrorEvidence);
                }
            }
            let status = raw_u64(raw, 224).map_err(invalid)?;
            let before_status = raw_u64(raw, BEFORE_CPU + 40).map_err(invalid)?;
            let preserves_uncorrectable = row.corrected
                && before_status & ((1_u64 << 63) | (1_u64 << 61))
                    == ((1_u64 << 63) | (1_u64 << 61));
            let expected_status = if preserves_uncorrectable {
                before_status | (1_u64 << 62)
            } else if before_status & (1_u64 << 63) != 0 {
                status | (1_u64 << 62)
            } else {
                status
            };
            if status & row.status_required != row.status_required
                || status & !row.status_allowed != 0
                || raw_u64(raw, QUEUED_CPU + 40).map_err(invalid)? != expected_status
                || raw_u64(raw, AFTER_CPU + 40).map_err(invalid)? != expected_status
                || (!preserves_uncorrectable
                    && raw_u64(raw, AFTER_CPU + 48).map_err(invalid)? != address)
            {
                return Err(FaultCommandBridgeError::HardwareErrorEvidence);
            }
        }
        FaultHardwareErrorMechanismV1::AcpiGhes => {
            for offset in [BEFORE_GHES, QUEUED_GHES, AFTER_GHES] {
                if raw[offset..offset + 8] != *b"CRUCGHS1"
                    || raw_u32(raw, offset + 16).map_err(invalid)? != 172
                {
                    return Err(FaultCommandBridgeError::HardwareErrorEvidence);
                }
            }
            if raw_u64(raw, BEFORE_GHES + 8).map_err(invalid)? == 0
                || !validate_ghes_memory_record(raw, QUEUED_GHES, row.corrected, address)?
                || raw[QUEUED_GHES..QUEUED_GHES + 192] != raw[AFTER_GHES..AFTER_GHES + 192]
            {
                return Err(FaultCommandBridgeError::HardwareErrorEvidence);
            }
        }
        FaultHardwareErrorMechanismV1::Aarch64Ras => {
            return Err(FaultCommandBridgeError::HardwareErrorEvidence);
        }
    }
    Ok(raw.to_vec())
}

fn validate_ghes_memory_record(
    raw: &[u8],
    state_offset: usize,
    corrected: bool,
    address: u64,
) -> Result<bool, FaultCommandBridgeError> {
    const MEMORY_SECTION_GUID: [u8; 16] = [
        0x14, 0x11, 0xbc, 0xa5, 0x64, 0x6f, 0xde, 0x4e, 0xb8, 0x63, 0x3e, 0x83, 0xed, 0x7c, 0x83,
        0xb1,
    ];
    const MEMORY_VALIDATION_BITS: u64 =
        (1_u64 << 14) | (1_u64 << 15) | (1_u64 << 6) | (1_u64 << 4) | (1_u64 << 1);
    let invalid = |_| FaultCommandBridgeError::HardwareErrorEvidence;
    let record = state_offset + 20;
    let block_status = if corrected { 0x12 } else { 0x11 };
    let severity = if corrected { 2 } else { 0 };

    Ok(raw_u64(raw, state_offset + 8).map_err(invalid)? == 0
        && raw_u32(raw, state_offset + 16).map_err(invalid)? == 172
        && raw_u32(raw, record).map_err(invalid)? == block_status
        && raw[record + 4..record + 12].iter().all(|byte| *byte == 0)
        && raw_u32(raw, record + 12).map_err(invalid)? == 152
        && raw_u32(raw, record + 16).map_err(invalid)? == severity
        && raw[record + 20..record + 36] == MEMORY_SECTION_GUID
        && raw_u32(raw, record + 36).map_err(invalid)? == severity
        && raw_u16(raw, record + 40).map_err(invalid)? == 0x300
        && raw[record + 42..record + 44].iter().all(|byte| *byte == 0)
        && raw_u32(raw, record + 44).map_err(invalid)? == 80
        && raw[record + 48..record + 92].iter().all(|byte| *byte == 0)
        && raw_u64(raw, record + 92).map_err(invalid)? == MEMORY_VALIDATION_BITS
        && raw_u64(raw, record + 100).map_err(invalid)? == 0
        && raw_u64(raw, record + 108).map_err(invalid)? == address
        && raw[record + 116..record + 172]
            .iter()
            .all(|byte| *byte == 0))
}

fn instruction_system_digest(
    cpu_sha256: [u8; 32],
    ram_sha256: [u8; 32],
    device_sha256: [u8; 32],
    ram_bytes: u64,
    device_bytes: u64,
) -> [u8; 32] {
    let mut digest = sha2::Sha256::new();
    digest.update(b"crucible.instruction-state.v1\0");
    digest.update(cpu_sha256);
    digest.update(ram_sha256);
    digest.update(device_sha256);
    digest.update(ram_bytes.to_le_bytes());
    digest.update(device_bytes.to_le_bytes());
    digest.finalize().into()
}

fn clock_json_u64(value: &serde_json::Value, name: &str) -> Option<u64> {
    value.as_object()?.get(name)?.as_u64()
}

fn clock_json_i64_table(value: &serde_json::Value) -> Option<Vec<i64>> {
    value
        .as_array()?
        .iter()
        .map(serde_json::Value::as_i64)
        .collect()
}

fn clock_timer_opportunity(
    source_id: [u8; 32],
    arm_sequence: u64,
    phase: u16,
    role: u16,
    index: u32,
    transform_generation: u64,
) -> u64 {
    let mut material = [0_u8; 64];
    material[..8].copy_from_slice(b"CRUCTMR1");
    material[8..40].copy_from_slice(&source_id);
    material[40..48].copy_from_slice(&arm_sequence.to_le_bytes());
    material[48..50].copy_from_slice(&phase.to_le_bytes());
    material[50..52].copy_from_slice(&role.to_le_bytes());
    material[52..56].copy_from_slice(&index.to_le_bytes());
    material[56..64].copy_from_slice(&transform_generation.to_le_bytes());
    let digest = sha2::Sha256::digest(material);
    let mut selected = [0_u8; 8];
    selected.copy_from_slice(&digest[..8]);
    match u64::from_le_bytes(selected) {
        0 => u64::MAX,
        opportunity => opportunity,
    }
}

fn clock_timer_table_index(
    binding_hash: [u8; 32],
    source_id: [u8; 32],
    timer_opportunity: u64,
    count: usize,
) -> Option<usize> {
    if count == 0 {
        return None;
    }
    let mut material = [0_u8; 80];
    material[..8].copy_from_slice(b"CRUCKEY1");
    material[8..40].copy_from_slice(&binding_hash);
    material[40..72].copy_from_slice(&source_id);
    material[72..80].copy_from_slice(&timer_opportunity.to_le_bytes());
    let digest = sha2::Sha256::digest(material);
    let selected = u64::from_le_bytes(digest[..8].try_into().ok()?);
    usize::try_from(selected % u64::try_from(count).ok()?).ok()
}

fn validate_clock_timer_observation(
    observation: &FaultClockObservationV1,
    source_id: [u8; 32],
    transform_generation: u64,
) -> Option<(u16, i64)> {
    let FaultClockObservationV1::TimerTransition {
        role,
        index,
        opportunity_phase,
        jitter_contribution,
        timer_opportunity,
        arm_sequence,
        ..
    } = observation
    else {
        return None;
    };
    if !matches!(*opportunity_phase, 29 | 30)
        || *timer_opportunity
            != clock_timer_opportunity(
                source_id,
                *arm_sequence,
                *opportunity_phase,
                *role,
                *index,
                transform_generation,
            )
    {
        return None;
    }
    Some((*opportunity_phase, *jitter_contribution))
}

fn validate_clock_observation_parameters(
    observation: &FaultClockObservationV1,
    expectation: &ClockCommandExpectation,
    source_id: [u8; 32],
    transform_generation: u64,
) -> bool {
    match (&expectation.parameters, observation) {
        (ClockCommandParameters::Remove, _) => false,
        (
            ClockCommandParameters::Transform {
                kind,
                signed_value,
                ratio,
                unsigned_value,
                process: _,
                monotonicity,
                overdue_policy,
            },
            FaultClockObservationV1::Impulse {
                transform_kind,
                signed_value: observed_signed,
                ratio: observed_ratio,
                unsigned_value: observed_unsigned,
                new_monotonicity,
                new_overdue_policy,
                ..
            },
        ) => {
            transform_kind == kind
                && observed_signed == signed_value
                && observed_ratio == ratio
                && observed_unsigned == unsigned_value
                && new_monotonicity == monotonicity
                && new_overdue_policy == overdue_policy
        }
        (
            ClockCommandParameters::Transform {
                kind,
                unsigned_value,
                process,
                monotonicity,
                overdue_policy,
                ..
            },
            FaultClockObservationV1::Read {
                transform_kind,
                contribution,
                monotonicity: observed_monotonicity,
                overdue_policy: observed_overdue,
                freeze_release,
                ..
            },
        ) => {
            let contribution_valid = match *kind {
                1..=4 => *contribution == 0,
                5 => process
                    .as_ref()
                    .and_then(clock_json_i64_table)
                    .is_some_and(|values| {
                        values.contains(contribution)
                            && contribution.unsigned_abs() <= *unsigned_value
                    }),
                6 => process.as_ref().is_some_and(|value| {
                    clock_json_u64(value, "maximum_offset_nanos")
                        .is_some_and(|maximum| contribution.unsigned_abs() <= maximum)
                }),
                _ => false,
            };
            let freeze_valid = if *kind == 4 {
                process.as_ref().is_some_and(|value| {
                    matches!(
                        (value.as_str(), *freeze_release),
                        (Some("resume_from_frozen"), 1) | (Some("catch_up_jump"), 2)
                    )
                })
            } else {
                true
            };
            transform_kind == kind
                && observed_monotonicity == monotonicity
                && observed_overdue == overdue_policy
                && contribution_valid
                && freeze_valid
        }
        (
            ClockCommandParameters::Transform {
                kind: 6, process, ..
            },
            FaultClockObservationV1::Wander {
                offsets,
                rates_ppb,
                next_nanos,
                sequences,
                ..
            },
        ) => process.as_ref().is_some_and(|value| {
            let Some(step) = clock_json_u64(value, "step_nanos") else {
                return false;
            };
            let Some(maximum_offset) = clock_json_u64(value, "maximum_offset_nanos") else {
                return false;
            };
            let Some(maximum_rate) = clock_json_u64(value, "maximum_rate_ppb") else {
                return false;
            };
            let Some(increments) = value
                .as_object()
                .and_then(|object| object.get("increments_ppb"))
                .and_then(clock_json_i64_table)
            else {
                return false;
            };
            offsets
                .iter()
                .all(|offset| offset.unsigned_abs() <= maximum_offset)
                && rates_ppb
                    .iter()
                    .all(|rate| rate.unsigned_abs() <= maximum_rate)
                && rates_ppb[1]
                    .checked_sub(rates_ppb[0])
                    .is_some_and(|delta| increments.contains(&delta))
                && next_nanos[1].checked_sub(next_nanos[0]) == Some(step)
                && sequences[1].checked_sub(sequences[0]) == Some(1)
        }),
        (
            ClockCommandParameters::Transform {
                kind,
                unsigned_value,
                process,
                ..
            },
            FaultClockObservationV1::TimerTransition {
                timer_opportunity, ..
            },
        ) => validate_clock_timer_observation(observation, source_id, transform_generation)
            .is_some_and(|(phase, contribution)| {
                if phase != expectation.model_phase {
                    return false;
                }
                if *kind != 5 {
                    return contribution == 0;
                }
                process
                    .as_ref()
                    .and_then(clock_json_i64_table)
                    .and_then(|values| {
                        let index = clock_timer_table_index(
                            expectation.binding_hash,
                            source_id,
                            *timer_opportunity,
                            values.len(),
                        )?;
                        values.get(index).copied()
                    })
                    .is_some_and(|selected| {
                        selected == contribution && selected.unsigned_abs() <= *unsigned_value
                    })
            }),
        (
            ClockCommandParameters::SourceState {
                transition,
                synchronization,
            },
            FaultClockObservationV1::SourceTransition {
                states,
                new_fallback,
                synchronization_ratio,
                synchronization_threshold_nanos,
                ..
            },
        ) => {
            let Some(kind) = transition.get("kind").and_then(serde_json::Value::as_str) else {
                return false;
            };
            let expected_state = match kind {
                "healthy" => 1,
                "degraded" => 2,
                "failed" => match transition
                    .pointer("/parameters/behavior")
                    .and_then(serde_json::Value::as_str)
                {
                    Some("stop") => 3,
                    Some("read_error") => 4,
                    _ => return false,
                },
                "fallback" => 5,
                _ => return false,
            };
            let fallback_valid = if kind == "fallback" {
                transition
                    .pointer("/parameters/source")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|source| {
                        crucible_shmem::fault_object_id_hash_v1(source) == *new_fallback
                    })
            } else {
                *new_fallback == [0; 32]
            };
            let synchronization_valid = match synchronization
                .get("kind")
                .and_then(serde_json::Value::as_str)
            {
                Some("step") => {
                    *synchronization_ratio == [0, 0] && *synchronization_threshold_nanos == 0
                }
                Some("slew") => {
                    let numerator = synchronization
                        .pointer("/parameters/rate/numerator")
                        .and_then(serde_json::Value::as_u64);
                    let denominator = synchronization
                        .pointer("/parameters/rate/denominator")
                        .and_then(serde_json::Value::as_u64);
                    let threshold = synchronization
                        .pointer("/parameters/threshold_nanos")
                        .and_then(serde_json::Value::as_u64);
                    numerator == Some(synchronization_ratio[0])
                        && denominator == Some(synchronization_ratio[1])
                        && threshold == Some(*synchronization_threshold_nanos)
                }
                _ => false,
            };
            states[1] == expected_state && fallback_valid && synchronization_valid
        }
        (
            ClockCommandParameters::SourceState { transition, .. },
            FaultClockObservationV1::Read {
                transform_kind,
                source_state,
                contribution,
                ..
            },
        ) => {
            let expected_state = match transition.get("kind").and_then(serde_json::Value::as_str) {
                Some("healthy") => 1,
                Some("degraded") => 2,
                Some("failed")
                    if transition
                        .pointer("/parameters/behavior")
                        .and_then(serde_json::Value::as_str)
                        == Some("stop") =>
                {
                    3
                }
                Some("failed") => 4,
                Some("fallback") => 5,
                _ => return false,
            };
            *transform_kind == 0 && *contribution == 0 && *source_state == expected_state
        }
        (
            ClockCommandParameters::SourceState { .. },
            FaultClockObservationV1::TimerTransition { .. },
        ) => validate_clock_timer_observation(observation, source_id, transform_generation)
            .is_some_and(|(_, contribution)| contribution == 0),
        _ => false,
    }
}

fn validate_clock_read_architecture(
    observation: &FaultClockObservationV1,
    row: &FaultClockCapabilityRowV1,
) -> bool {
    let FaultClockObservationV1::Read {
        raw_value,
        transformed_value,
        raw_architectural_value,
        transformed_architectural_value,
        source_width_bits,
        wrap_action,
        read_error,
        ..
    } = observation
    else {
        return true;
    };
    if u32::from(*source_width_bits) != row.width_bits || *wrap_action > 1 {
        return false;
    }
    let normalized_raw = u128::from(*raw_architectural_value)
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_mul(u128::from(row.frequency_denominator)))
        .map(|value| value / u128::from(row.frequency_numerator));
    if normalized_raw != Some(u128::from(*raw_value)) {
        return false;
    }
    if *read_error {
        return *transformed_architectural_value == *raw_architectural_value && *wrap_action == 0;
    }
    let Some(ticks) = u128::from(*transformed_value)
        .checked_mul(u128::from(row.frequency_numerator))
        .map(|value| value / (1_000_000_000_u128 * u128::from(row.frequency_denominator)))
    else {
        return false;
    };
    let mask = if row.width_bits == 64 {
        u128::from(u64::MAX)
    } else {
        (1_u128 << row.width_bits) - 1
    };
    let wrapped = ticks & !mask != 0;
    ticks & mask == u128::from(*transformed_architectural_value)
        && *wrap_action == u16::from(wrapped)
        && (!wrapped || row.flags & 1 != 0)
}

fn translate_clock_evidence(
    raw: &[u8],
    manifest_payload: &[u8],
    event: &QemuFaultEvent,
    observed_icount: u64,
    expectation: &ClockCommandExpectation,
) -> Result<Vec<u8>, FaultCommandBridgeError> {
    fn invalid<T>(_: T) -> FaultCommandBridgeError {
        FaultCommandBridgeError::ClockEvidence
    }
    if raw.starts_with(b"CRUCCIM1") {
        return translate_clock_impulse_event_evidence(
            raw,
            manifest_payload,
            event,
            observed_icount,
            expectation,
        );
    }
    let read_record = raw.starts_with(b"CRUCCRE1");
    if expectation.operation != NodeFaultOperationV1::Upsert
        || raw.len() != if read_record { 416 } else { 384 }
        || raw_u16(raw, 8).map_err(invalid)? != 1
    {
        return Err(FaultCommandBridgeError::ClockEvidence);
    }
    let source_kind = raw_u16(raw, 10).map_err(invalid)?;
    let (
        source_offset,
        binding_offset,
        before_offset,
        after_offset,
        generation,
        opportunity,
        observation,
    ) = match &raw[..8] {
        b"CRUCCRE1" => {
            if raw_u64(raw, 16).map_err(invalid)? != event.observed_icount
                || raw[404..].iter().any(|byte| *byte != 0)
            {
                return Err(FaultCommandBridgeError::ClockEvidence);
            }
            (
                128,
                160,
                192,
                224,
                raw_u64(raw, 96).map_err(invalid)?,
                raw_u64(raw, 24).map_err(invalid)?,
                FaultClockObservationV1::Read {
                    raw_value: raw_u64(raw, 32).map_err(invalid)?,
                    transformed_value: raw_u64(raw, 40).map_err(invalid)?,
                    raw_architectural_value: raw_u64(raw, 384).map_err(invalid)?,
                    transformed_architectural_value: raw_u64(raw, 392).map_err(invalid)?,
                    source_width_bits: raw_u16(raw, 400).map_err(invalid)?,
                    wrap_action: raw_u16(raw, 402).map_err(invalid)?,
                    anchor_raw: raw_u64(raw, 48).map_err(invalid)?,
                    anchor_value: raw_u64(raw, 56).map_err(invalid)?,
                    drift_ratio: [
                        raw_u64(raw, 64).map_err(invalid)?,
                        raw_u64(raw, 72).map_err(invalid)?,
                    ],
                    additive_nanos: raw_u64(raw, 80).map_err(invalid)? as i64,
                    frozen_value: raw_u64(raw, 88).map_err(invalid)?,
                    read_error: match raw_u32(raw, 12).map_err(invalid)? {
                        0 => false,
                        1 => true,
                        _ => return Err(FaultCommandBridgeError::ClockEvidence),
                    },
                    read_opportunity: raw_u64(raw, 264).map_err(invalid)?,
                    transform_kind: raw_u32(raw, 256).map_err(invalid)?,
                    contribution: raw_u64(raw, 272).map_err(invalid)? as i64,
                    monotonicity: raw_u32(raw, 104).map_err(invalid)?,
                    overdue_policy: raw_u32(raw, 108).map_err(invalid)?,
                    source_state: raw_u32(raw, 112).map_err(invalid)?,
                    freeze_release: raw_u32(raw, 116).map_err(invalid)?,
                    synchronization_remaining_nanos: raw_u64(raw, 120).map_err(invalid)? as i64,
                },
            )
        }
        b"CRUCCWE1"
            if raw[12..16].iter().all(|byte| *byte == 0)
                && raw[240..].iter().all(|byte| *byte == 0) =>
        {
            (
                104,
                136,
                168,
                200,
                raw_u64(raw, 96).map_err(invalid)?,
                raw_u64(raw, 232).map_err(invalid)?,
                FaultClockObservationV1::Wander {
                    scheduler_nanos: raw_u64(raw, 16).map_err(invalid)?,
                    raw_nanos: raw_u64(raw, 24).map_err(invalid)?,
                    offsets: [
                        raw_u64(raw, 32).map_err(invalid)? as i64,
                        raw_u64(raw, 40).map_err(invalid)? as i64,
                    ],
                    rates_ppb: [
                        raw_u64(raw, 48).map_err(invalid)? as i64,
                        raw_u64(raw, 56).map_err(invalid)? as i64,
                    ],
                    next_nanos: [
                        raw_u64(raw, 64).map_err(invalid)?,
                        raw_u64(raw, 72).map_err(invalid)?,
                    ],
                    sequences: [
                        raw_u64(raw, 80).map_err(invalid)?,
                        raw_u64(raw, 88).map_err(invalid)?,
                    ],
                },
            )
        }
        b"CRUCCSE1"
            if raw[20..24].iter().all(|byte| *byte == 0)
                && raw[312..].iter().all(|byte| *byte == 0) =>
        {
            (
                64,
                160,
                192,
                224,
                raw_u64(raw, 304).map_err(invalid)?,
                raw_u64(raw, 296).map_err(invalid)?,
                FaultClockObservationV1::SourceTransition {
                    scheduler_nanos: raw_u64(raw, 24).map_err(invalid)?,
                    raw_nanos: raw_u64(raw, 32).map_err(invalid)?,
                    states: [
                        raw_u32(raw, 12).map_err(invalid)?,
                        raw_u32(raw, 16).map_err(invalid)?,
                    ],
                    old_value: raw_u64(raw, 40).map_err(invalid)?,
                    new_anchor_value: raw_u64(raw, 48).map_err(invalid)?,
                    transition_generation: raw_u64(raw, 56).map_err(invalid)?,
                    old_fallback: raw[96..128].try_into().map_err(invalid)?,
                    new_fallback: raw[128..160].try_into().map_err(invalid)?,
                    synchronization_remaining_nanos: [
                        raw_u64(raw, 256).map_err(invalid)? as i64,
                        raw_u64(raw, 264).map_err(invalid)? as i64,
                    ],
                    synchronization_ratio: [
                        raw_u64(raw, 272).map_err(invalid)?,
                        raw_u64(raw, 280).map_err(invalid)?,
                    ],
                    synchronization_threshold_nanos: raw_u64(raw, 288).map_err(invalid)?,
                },
            )
        }
        b"CRUCCTE1"
            if raw[14..16].iter().all(|byte| *byte == 0)
                && raw[226..232].iter().all(|byte| *byte == 0)
                && raw[256..].iter().all(|byte| *byte == 0) =>
        {
            (
                88,
                120,
                152,
                184,
                raw_u64(raw, 80).map_err(invalid)?,
                raw_u64(raw, 216).map_err(invalid)?,
                FaultClockObservationV1::TimerTransition {
                    role: raw_u16(raw, 12).map_err(invalid)?,
                    index: raw_u32(raw, 16).map_err(invalid)?,
                    action: raw_u32(raw, 20).map_err(invalid)?,
                    sequence: raw_u64(raw, 24).map_err(invalid)?,
                    old_deadlines: [
                        raw_u64(raw, 32).map_err(invalid)?,
                        raw_u64(raw, 40).map_err(invalid)?,
                    ],
                    new_deadlines: [
                        raw_u64(raw, 56).map_err(invalid)?,
                        raw_u64(raw, 64).map_err(invalid)?,
                    ],
                    generations: [
                        raw_u64(raw, 48).map_err(invalid)?,
                        raw_u64(raw, 72).map_err(invalid)?,
                    ],
                    opportunity_phase: raw_u16(raw, 224).map_err(invalid)?,
                    jitter_contribution: raw_u64(raw, 232).map_err(invalid)? as i64,
                    timer_opportunity: raw_u64(raw, 240).map_err(invalid)?,
                    arm_sequence: raw_u64(raw, 248).map_err(invalid)?,
                },
            )
        }
        _ => return Err(FaultCommandBridgeError::ClockEvidence),
    };
    let source_id: [u8; 32] = raw[source_offset..source_offset + 32]
        .try_into()
        .map_err(invalid)?;
    let binding_hash: [u8; 32] = raw[binding_offset..binding_offset + 32]
        .try_into()
        .map_err(invalid)?;
    let before_hash: [u8; 32] = raw[before_offset..before_offset + 32]
        .try_into()
        .map_err(invalid)?;
    let after_hash: [u8; 32] = raw[after_offset..after_offset + 32]
        .try_into()
        .map_err(invalid)?;
    let manifest = FaultClockCapabilityManifestV1::decode(manifest_payload).map_err(invalid)?;
    let Some(row) = manifest.rows.iter().find(|row| {
        row.source_kind == source_kind
            && crucible_shmem::fault_object_id_hash_v1(&row.id) == source_id
    }) else {
        return Err(FaultCommandBridgeError::ClockEvidence);
    };
    if binding_hash != event.binding_hash
        || event.command_kind != expectation.command_kind
        || binding_hash != expectation.binding_hash
        || event.model_phase != expectation.model_phase
        || !expectation.source_ids.contains(&source_id)
        || before_hash != event.before_hash
        || after_hash != event.after_hash
        || !validate_clock_observation_parameters(&observation, expectation, source_id, generation)
        || !validate_clock_read_architecture(&observation, row)
    {
        return Err(FaultCommandBridgeError::ClockEvidence);
    }
    FaultClockEvidenceV1 {
        source_kind,
        model_phase: event.model_phase,
        observed_icount,
        source_id,
        binding_hash,
        before_hash,
        after_hash,
        manifest_sha256: sha2::Sha256::digest(manifest_payload).into(),
        transform_generation: generation,
        opportunity,
        observation,
    }
    .encode()
    .map_err(invalid)
}

fn translate_clock_impulse_event_evidence(
    raw: &[u8],
    manifest_payload: &[u8],
    event: &QemuFaultEvent,
    observed_icount: u64,
    expectation: &ClockCommandExpectation,
) -> Result<Vec<u8>, FaultCommandBridgeError> {
    fn invalid<T>(_: T) -> FaultCommandBridgeError {
        FaultCommandBridgeError::ClockEvidence
    }
    validate_raw_clock_impulse(raw)?;
    let source_kind = raw_u16(raw, 210).map_err(invalid)?;
    let source_id: [u8; 32] = raw[80..112].try_into().map_err(invalid)?;
    let binding_hash: [u8; 32] = raw[112..144].try_into().map_err(invalid)?;
    let before_hash: [u8; 32] = raw[144..176].try_into().map_err(invalid)?;
    let after_hash: [u8; 32] = raw[176..208].try_into().map_err(invalid)?;
    let model_phase = raw_u16(raw, 208).map_err(invalid)?;
    let manifest = FaultClockCapabilityManifestV1::decode(manifest_payload).map_err(invalid)?;
    let observation = decode_clock_impulse_observation(raw)?;
    if expectation.operation != NodeFaultOperationV1::Apply
        || expectation.command_kind != FaultCommandKind::ClockTransform as u16
        || event.command_kind != expectation.command_kind
        || raw_u64(raw, 16).map_err(invalid)? != event.observed_icount
        || event.model_phase != model_phase
        || event.model_phase != expectation.model_phase
        || event.binding_hash != binding_hash
        || expectation.binding_hash != binding_hash
        || event.before_hash != before_hash
        || event.after_hash != after_hash
        || !expectation.source_ids.contains(&source_id)
        || !manifest.rows.iter().any(|row| {
            row.source_kind == source_kind
                && crucible_shmem::fault_object_id_hash_v1(&row.id) == source_id
        })
        || !validate_clock_observation_parameters(
            &observation,
            expectation,
            source_id,
            raw_u64(raw, 72).map_err(invalid)?,
        )
    {
        return Err(FaultCommandBridgeError::ClockEvidence);
    }
    FaultClockEvidenceV1 {
        source_kind,
        model_phase,
        observed_icount,
        source_id,
        binding_hash,
        before_hash,
        after_hash,
        manifest_sha256: sha2::Sha256::digest(manifest_payload).into(),
        transform_generation: raw_u64(raw, 72).map_err(invalid)?,
        opportunity: 0,
        observation,
    }
    .encode()
    .map_err(invalid)
}

fn validate_raw_clock_impulse(raw: &[u8]) -> Result<(), FaultCommandBridgeError> {
    fn invalid<T>(_: T) -> FaultCommandBridgeError {
        FaultCommandBridgeError::ClockEvidence
    }
    if raw.len() != 384
        || &raw[..8] != b"CRUCCIM1"
        || raw_u16(raw, 8).map_err(invalid)? != 1
        || raw[12..16].iter().any(|byte| *byte != 0)
        || raw[276..].iter().any(|byte| *byte != 0)
    {
        return Err(FaultCommandBridgeError::ClockEvidence);
    }
    Ok(())
}

fn decode_clock_impulse_observation(
    raw: &[u8],
) -> Result<FaultClockObservationV1, FaultCommandBridgeError> {
    fn invalid<T>(_: T) -> FaultCommandBridgeError {
        FaultCommandBridgeError::ClockEvidence
    }
    Ok(FaultClockObservationV1::Impulse {
        transform_kind: raw_u16(raw, 10).map_err(invalid)? as u32,
        raw_nanos: raw_u64(raw, 24).map_err(invalid)?,
        old_value: raw_u64(raw, 32).map_err(invalid)?,
        signed_value: raw_u64(raw, 40).map_err(invalid)? as i64,
        ratio: [
            raw_u64(raw, 48).map_err(invalid)?,
            raw_u64(raw, 56).map_err(invalid)?,
        ],
        unsigned_value: raw_u64(raw, 64).map_err(invalid)?,
        new_anchor: [
            raw_u64(raw, 212).map_err(invalid)?,
            raw_u64(raw, 220).map_err(invalid)?,
        ],
        new_drift_ratio: [
            raw_u64(raw, 228).map_err(invalid)?,
            raw_u64(raw, 236).map_err(invalid)?,
        ],
        new_additive_nanos: raw_u64(raw, 244).map_err(invalid)? as i64,
        new_frozen_value: raw_u64(raw, 252).map_err(invalid)?,
        new_freeze_release: raw_u32(raw, 260).map_err(invalid)?,
        new_monotonicity: raw_u32(raw, 264).map_err(invalid)?,
        new_overdue_policy: raw_u32(raw, 268).map_err(invalid)?,
        new_source_state: raw_u32(raw, 272).map_err(invalid)?,
    })
}

fn translate_clock_impulse_evidence(
    raw: &[u8],
    manifest_payload: &[u8],
    result: &QemuFaultResult,
    logical_icount_offset: u64,
    expectation: &ClockCommandExpectation,
) -> Result<Vec<u8>, FaultCommandBridgeError> {
    fn invalid<T>(_: T) -> FaultCommandBridgeError {
        FaultCommandBridgeError::ClockEvidence
    }
    validate_raw_clock_impulse(raw)?;
    let source_kind = raw_u16(raw, 210).map_err(invalid)?;
    let source_id: [u8; 32] = raw[80..112].try_into().map_err(invalid)?;
    let binding_hash: [u8; 32] = raw[112..144].try_into().map_err(invalid)?;
    let before_hash: [u8; 32] = raw[144..176].try_into().map_err(invalid)?;
    let after_hash: [u8; 32] = raw[176..208].try_into().map_err(invalid)?;
    let manifest = FaultClockCapabilityManifestV1::decode(manifest_payload).map_err(invalid)?;
    let observation = decode_clock_impulse_observation(raw)?;
    if expectation.operation != NodeFaultOperationV1::Apply
        || before_hash != result.before_hash
        || after_hash != result.after_hash
        || result.command_kind != expectation.command_kind
        || binding_hash != expectation.binding_hash
        || raw_u64(raw, 16).map_err(invalid)? != result.observed_icount
        || result.applied_icount != result.observed_icount
        || raw_u16(raw, 208).map_err(invalid)? != expectation.model_phase
        || !expectation.source_ids.contains(&source_id)
        || !manifest.rows.iter().any(|row| {
            row.source_kind == source_kind
                && crucible_shmem::fault_object_id_hash_v1(&row.id) == source_id
        })
        || !validate_clock_observation_parameters(
            &observation,
            expectation,
            source_id,
            raw_u64(raw, 72).map_err(invalid)?,
        )
    {
        return Err(FaultCommandBridgeError::ClockEvidence);
    }
    let observed_icount = raw_u64(raw, 16)
        .map_err(invalid)?
        .checked_add(logical_icount_offset)
        .ok_or(FaultCommandBridgeError::CoordinateOverflow)?;
    FaultClockEvidenceV1 {
        source_kind,
        model_phase: raw_u16(raw, 208).map_err(invalid)?,
        observed_icount,
        source_id,
        binding_hash,
        before_hash,
        after_hash,
        manifest_sha256: sha2::Sha256::digest(manifest_payload).into(),
        transform_generation: raw_u64(raw, 72).map_err(invalid)?,
        opportunity: 0,
        observation,
    }
    .encode()
    .map_err(invalid)
}

fn raw_u16(bytes: &[u8], offset: usize) -> Result<u16, FaultCommandBridgeError> {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(FaultCommandBridgeError::RegisterEvidence)
}

fn raw_u32(bytes: &[u8], offset: usize) -> Result<u32, FaultCommandBridgeError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(FaultCommandBridgeError::RegisterEvidence)
}

fn raw_u64(bytes: &[u8], offset: usize) -> Result<u64, FaultCommandBridgeError> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(FaultCommandBridgeError::RegisterEvidence)
}

fn accelerator_field(
    expectation: &AcceleratorCommandExpectation,
    tag: u16,
) -> Result<&[u8], FaultCommandBridgeError> {
    expectation
        .fields
        .get(&tag)
        .map(Vec::as_slice)
        .ok_or(FaultCommandBridgeError::AcceleratorEvidence)
}

fn accelerator_u32(
    expectation: &AcceleratorCommandExpectation,
    tag: u16,
) -> Result<u32, FaultCommandBridgeError> {
    accelerator_field(expectation, tag)?
        .try_into()
        .map(u32::from_le_bytes)
        .map_err(|_| FaultCommandBridgeError::AcceleratorEvidence)
}

fn accelerator_u64(
    expectation: &AcceleratorCommandExpectation,
    tag: u16,
) -> Result<u64, FaultCommandBridgeError> {
    accelerator_field(expectation, tag)?
        .try_into()
        .map(u64::from_le_bytes)
        .map_err(|_| FaultCommandBridgeError::AcceleratorEvidence)
}

fn accelerator_bool(
    expectation: &AcceleratorCommandExpectation,
    tag: u16,
) -> Result<bool, FaultCommandBridgeError> {
    match accelerator_field(expectation, tag)? {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(FaultCommandBridgeError::AcceleratorEvidence),
    }
}

fn translate_accelerator_evidence(
    raw: &[u8],
    event: &QemuFaultEvent,
    manifest_payload: &[u8],
    expectation: &AcceleratorCommandExpectation,
) -> Result<Vec<u8>, FaultCommandBridgeError> {
    use node_fault_field::*;

    if raw.len() != 256
        || event.command_kind != expectation.command_kind
        || event.binding_hash != expectation.binding_hash
        || event.generation != expectation.generation
        || event.action_hash != expectation.action_hash
        || event.target_hash != expectation.target_hash
        || event.model_phase != expectation.model_phase
        || event.outcome != FaultEventOutcomeV1::Applied as u16
    {
        return Err(FaultCommandBridgeError::AcceleratorEvidence);
    }
    let manifest = FaultAcceleratorCapabilityManifestV1::decode(manifest_payload)
        .map_err(|_| FaultCommandBridgeError::AcceleratorEvidence)?;
    let device = accelerator_field(expectation, T1)?;
    let row = manifest
        .rows
        .iter()
        .find(|row| fault_object_id_hash_v1(&row.id).as_slice() == device)
        .ok_or(FaultCommandBridgeError::AcceleratorEvidence)?;
    let common = |before_at: usize, after_at: usize, binding_at: usize| {
        if raw.get(before_at..before_at + 32) != Some(event.before_hash.as_slice())
            || raw.get(after_at..after_at + 32) != Some(event.after_hash.as_slice())
            || raw.get(binding_at..binding_at + 32) != Some(expectation.binding_hash.as_slice())
        {
            Err(FaultCommandBridgeError::AcceleratorEvidence)
        } else {
            Ok(())
        }
    };
    match raw.get(..8) {
        Some(b"CRUCALE1")
            if expectation.command_kind == FaultCommandKind::AcceleratorLifecycle as u16 =>
        {
            if raw_u32(raw, 16)? != accelerator_u32(expectation, P2)?
                || raw_u32(raw, 20)? != accelerator_u32(expectation, P3)?
                || raw_u32(raw, 24)? != accelerator_u32(expectation, P4)?
                || raw.get(64..96) != Some(device)
            {
                return Err(FaultCommandBridgeError::AcceleratorEvidence);
            }
            common(96, 128, 200)?;
        }
        Some(b"CRUCAMI1")
            if expectation.command_kind == FaultCommandKind::AcceleratorMemoryEvent as u16 =>
        {
            let transform = accelerator_field(expectation, P8)?;
            if raw_u64(raw, 16)? != accelerator_u64(expectation, P1)?
                || raw_u64(raw, 24)? != accelerator_u64(expectation, P2)?
                || raw_u32(raw, 32)? != accelerator_u32(expectation, P4)?
                || raw_u32(raw, 36)? != u32::from(accelerator_bool(expectation, P5)?)
                || raw_u64(raw, 40)? != accelerator_u64(expectation, P6)?
                || raw.get(168..200) != Some(sha2::Sha256::digest(transform).as_slice())
            {
                return Err(FaultCommandBridgeError::AcceleratorEvidence);
            }
            common(72, 104, 136)?;
        }
        Some(b"CRUCAME1")
            if expectation.command_kind == FaultCommandKind::AcceleratorMemoryEvent as u16 =>
        {
            let transform = accelerator_field(expectation, P8)?;
            if raw_u64(raw, 24)? != accelerator_u64(expectation, P1)?
                || raw_u64(raw, 32)? != accelerator_u64(expectation, P2)?
                || raw_u32(raw, 40)? != accelerator_u32(expectation, P4)?
                || raw_u32(raw, 44)? != u32::from(accelerator_bool(expectation, P5)?)
                || raw_u64(raw, 48)? != accelerator_u64(expectation, P6)?
                || raw.get(168..200) != Some(sha2::Sha256::digest(transform).as_slice())
            {
                return Err(FaultCommandBridgeError::AcceleratorEvidence);
            }
            common(104, 136, 200)?;
        }
        Some(b"CRUCARE1")
            if expectation.command_kind == FaultCommandKind::AcceleratorResultTransform as u16 =>
        {
            let selector = policy_json(accelerator_field(expectation, P1)?, true)?;
            let mutation = policy_json(accelerator_field(expectation, P2)?, true)?;
            let offset = mutation
                .get("offset")
                .and_then(serde_json::Value::as_u64)
                .ok_or(FaultCommandBridgeError::AcceleratorEvidence)?;
            let mask = mutation
                .get("mask")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| hex::decode(value).ok())
                .ok_or(FaultCommandBridgeError::AcceleratorEvidence)?;
            let value = mutation
                .get("value")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| hex::decode(value).ok())
                .ok_or(FaultCommandBridgeError::AcceleratorEvidence)?;
            let class_id = raw_u16(raw, 8)?;
            let expected_job = match class_id {
                1 if row.class_mask & 1 != 0 => "vector-add",
                2 if row.class_mask & 2 != 0 => "matrix-multiply",
                3 if row.class_mask & 4 != 0 => "lookup-table",
                _ => return Err(FaultCommandBridgeError::AcceleratorEvidence),
            };
            let queue_id = u64::from(raw_u16(raw, 12)?);
            if raw_u64(raw, 24)? != offset
                || raw_u64(raw, 32)? != mask.len() as u64
                || selector.get("job_kind").and_then(serde_json::Value::as_str)
                    != Some(expected_job)
                || selector
                    .get("queue")
                    .and_then(serde_json::Value::as_u64)
                    .is_some_and(|queue| queue != queue_id)
                || queue_id < u64::from(row.queue_start)
                || queue_id > u64::from(row.queue_end)
                || raw_u64(raw, 40)? > u64::from(row.maximum_output_bytes)
                || raw.get(112..144) != Some(sha2::Sha256::digest(&mask).as_slice())
                || raw.get(144..176) != Some(sha2::Sha256::digest(&value).as_slice())
            {
                return Err(FaultCommandBridgeError::AcceleratorEvidence);
            }
            common(48, 80, 200)?;
        }
        Some(b"CRUCASE1")
            if expectation.command_kind == FaultCommandKind::AcceleratorService as u16 =>
        {
            let class_id = raw_u16(raw, 8)?;
            let ratio = accelerator_field(expectation, P1)?;
            let thermal = policy_json(accelerator_field(expectation, P6)?, true)?;
            if !(1..=3).contains(&class_id)
                || row.class_mask & (1 << (class_id - 1)) == 0
                || raw_u16(raw, 12)? < row.queue_start
                || raw_u16(raw, 12)? > row.queue_end
                || raw_u64(raw, 152)? > u64::from(row.maximum_input_bytes)
                || raw_u64(raw, 160)? > u64::from(row.maximum_output_bytes)
                || raw.get(40..56) != Some(ratio)
                || raw_u64(raw, 56)?
                    != if accelerator_bool(expectation, P2)? {
                        accelerator_u64(expectation, P3)?
                    } else {
                        u64::MAX
                    }
                || raw_u64(raw, 64)?
                    != if accelerator_bool(expectation, P4)? {
                        accelerator_u64(expectation, P5)?
                    } else {
                        u64::MAX
                    }
                || thermal
                    .get("temperature_millikelvin")
                    .and_then(serde_json::Value::as_u64)
                    != Some(raw_u64(raw, 136)?)
                || thermal
                    .get("power_milliwatts")
                    .and_then(serde_json::Value::as_u64)
                    != Some(raw_u64(raw, 144)?)
            {
                return Err(FaultCommandBridgeError::AcceleratorEvidence);
            }
            common_hashes(raw, event, 88, 168)?;
            if raw.get(168..200) != Some(expectation.binding_hash.as_slice()) {
                return Err(FaultCommandBridgeError::AcceleratorEvidence);
            }
        }
        _ => return Err(FaultCommandBridgeError::AcceleratorEvidence),
    }
    Ok(raw.to_vec())
}

fn common_hashes(
    raw: &[u8],
    event: &QemuFaultEvent,
    before_len: usize,
    after_len: usize,
) -> Result<(), FaultCommandBridgeError> {
    if sha2::Sha256::digest(&raw[..before_len]).as_slice() != event.before_hash
        || sha2::Sha256::digest(&raw[..after_len]).as_slice() != event.after_hash
    {
        return Err(FaultCommandBridgeError::AcceleratorEvidence);
    }
    Ok(())
}

fn boundary_phase(value: u16) -> Result<FaultBoundaryPhase, FaultCommandBridgeError> {
    match value {
        1 => Ok(FaultBoundaryPhase::NodeBoundary),
        2 => Ok(FaultBoundaryPhase::BeforeInstruction),
        3 => Ok(FaultBoundaryPhase::AfterInstruction),
        4 => Ok(FaultBoundaryPhase::BeforeMemoryAccess),
        5 => Ok(FaultBoundaryPhase::AfterMemoryAccess),
        6 => Ok(FaultBoundaryPhase::Interrupt),
        7 => Ok(FaultBoundaryPhase::Device),
        _ => Err(FaultCommandBridgeError::QemuPhase { value }),
    }
}

fn result_status(value: u16) -> Result<FaultResultStatus, FaultCommandBridgeError> {
    match value {
        1 => Ok(FaultResultStatus::Applied),
        2 => Ok(FaultResultStatus::NotApplicable),
        3 => Ok(FaultResultStatus::PreconditionMismatch),
        4 => Ok(FaultResultStatus::InvalidTarget),
        5 => Ok(FaultResultStatus::InvalidPhase),
        6 => Ok(FaultResultStatus::UnsupportedCapability),
        7 => Ok(FaultResultStatus::PastBoundary),
        8 => Ok(FaultResultStatus::ResourceLimit),
        9 => Ok(FaultResultStatus::GuestRejected),
        10 => Ok(FaultResultStatus::InternalError),
        11 => Ok(FaultResultStatus::MalformedCommand),
        12 => Ok(FaultResultStatus::DuplicateSequence),
        13 => Ok(FaultResultStatus::AuthenticationFailed),
        14 => Ok(FaultResultStatus::Prepared),
        _ => Err(FaultCommandBridgeError::QemuStatus { value }),
    }
}

fn event_outcome(value: u16) -> Result<FaultEventOutcomeV1, FaultCommandBridgeError> {
    match value {
        1 => Ok(FaultEventOutcomeV1::Applied),
        2 => Ok(FaultEventOutcomeV1::Suppressed),
        3 => Ok(FaultEventOutcomeV1::Corrected),
        4 => Ok(FaultEventOutcomeV1::Error),
        5 => Ok(FaultEventOutcomeV1::Passed),
        6 => Ok(FaultEventOutcomeV1::Recovered),
        _ => Err(FaultCommandBridgeError::QemuEventOutcome { value }),
    }
}

fn rejection_status(error: FaultAbiError) -> FaultResultStatus {
    match error {
        FaultAbiError::PayloadDigest => FaultResultStatus::AuthenticationFailed,
        _ => FaultResultStatus::MalformedCommand,
    }
}

/// Failure of the lossless fault command bridge.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FaultCommandBridgeError {
    /// A required patched-QEMU symbol is absent.
    #[error("required QEMU fault capability `{symbol}` is unavailable")]
    CapabilityUnavailable {
        /// Missing symbol.
        symbol: &'static str,
    },
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
    /// QEMU populated reserved event bytes.
    #[error("QEMU fault event returned nonzero reserved state")]
    QemuEventReserved,
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
mod tests {
    use super::*;
    use crucible_shmem::{
        DequeuedFaultResult, FAULT_COMMAND_ABI_MAJOR, FAULT_COMMAND_ABI_MINOR,
        FAULT_COMMAND_FLAG_NONE, FAULT_COMMAND_SEMANTIC_VERSION, dequeue_fault_result,
        enqueue_fault_command,
    };

    fn complete_x86_hardware_manifest(
        recoverable: FaultHardwareErrorCapabilityRowV1,
    ) -> FaultHardwareErrorCapabilityManifestV1 {
        let mut corrected = recoverable.clone();
        corrected.id = "x86.machine-check.corrected".to_owned();
        corrected.error_class = FaultHardwareErrorClassV1::Corrected;
        corrected.visibility_mask = crucible_shmem::FAULT_HARDWARE_ERROR_VISIBILITY_TELEMETRY;
        corrected.status_required = 1_u64 << 63;
        corrected.corrected = true;
        let mut fatal = recoverable.clone();
        fatal.id = "x86.machine-check.fatal".to_owned();
        fatal.error_class = FaultHardwareErrorClassV1::Fatal;
        fatal.status_required |= 1_u64 << 57;
        FaultHardwareErrorCapabilityManifestV1 {
            architecture: FaultCapabilityScope::X86_64,
            rows: vec![corrected, fatal, recoverable],
        }
    }

    fn complete_aarch64_hardware_manifest(
        corrected_memory: FaultHardwareErrorCapabilityRowV1,
    ) -> FaultHardwareErrorCapabilityManifestV1 {
        let ras = |id: &str, class, maskable: bool| FaultHardwareErrorCapabilityRowV1 {
            id: id.to_owned(),
            bank: "aarch64.ras.delivery-state".to_owned(),
            channel: "aarch64.memory.channel".to_owned(),
            rank: "aarch64.memory.rank".to_owned(),
            firmware: "aarch64-ras".to_owned(),
            state: if maskable {
                "aarch64-disr-serror".to_owned()
            } else {
                "aarch64-esr-far-data-abort".to_owned()
            },
            record_kind: FaultHardwareErrorRecordKindV1::Aarch64Ras,
            error_class: class,
            mechanism: FaultHardwareErrorMechanismV1::Aarch64Ras,
            visibility_mask: crucible_shmem::FAULT_HARDWARE_ERROR_VISIBILITY_EXCEPTION,
            bank_number: 0,
            bank_count: 1,
            vector: if maskable { 47 } else { 3 },
            status_required: 0,
            status_allowed: 0,
            syndrome_required: 0x10,
            syndrome_allowed: u32::MAX.into(),
            model_phase_mask: 1 << (11 - 1),
            privilege_mask: crucible_shmem::FAULT_HARDWARE_ERROR_PRIVILEGE_V1_MASK,
            corrected: false,
            maskable,
            vmstate: true,
        };
        let mut uncorrectable_memory = corrected_memory.clone();
        uncorrectable_memory.id = "memory.ecc.uncorrectable".to_owned();
        uncorrectable_memory.error_class = FaultHardwareErrorClassV1::Recoverable;
        uncorrectable_memory.visibility_mask =
            crucible_shmem::FAULT_HARDWARE_ERROR_VISIBILITY_EXCEPTION;
        uncorrectable_memory.corrected = false;
        let rows = vec![
            ras(
                "aarch64.ras.asynchronous",
                FaultHardwareErrorClassV1::Asynchronous,
                true,
            ),
            ras(
                "aarch64.ras.asynchronous-fatal",
                FaultHardwareErrorClassV1::Fatal,
                true,
            ),
            ras(
                "aarch64.ras.synchronous",
                FaultHardwareErrorClassV1::Synchronous,
                false,
            ),
            ras(
                "aarch64.ras.synchronous-fatal",
                FaultHardwareErrorClassV1::Fatal,
                false,
            ),
            corrected_memory,
            uncorrectable_memory,
        ];
        FaultHardwareErrorCapabilityManifestV1 {
            architecture: FaultCapabilityScope::Aarch64,
            rows,
        }
    }

    #[test]
    fn bridge_accepts_every_canonical_qemu_result_status() {
        for value in 1_u16..=14 {
            let status = result_status(value)
                .unwrap_or_else(|error| panic!("canonical status {value} was rejected: {error}"));
            assert_eq!(status as u16, value);
        }
        assert!(matches!(
            result_status(15),
            Err(FaultCommandBridgeError::QemuStatus { value: 15 })
        ));
    }

    #[test]
    fn bridge_translates_capabilities_and_local_rejections_at_logical_time() {
        const COMMAND_ARENA_OFFSET: u64 = 4_096;
        const RESULT_ARENA_OFFSET: u64 = 8_192;
        const EVENT_ARENA_OFFSET: u64 = 12_288;
        TEST_CAPABILITY_RESULT_PENDING.with(|pending| pending.set(None));
        let target_node_hash = *blake3::hash(b"node").as_bytes();
        let command_ring = RingHeader::new();
        let command_arena_header = FaultPayloadArenaHeader::new();
        let mut command_slots = vec![FaultCommandSlotV1::new(); 4];
        let mut command_arena = vec![0_u8; 512];
        let result_ring = RingHeader::new();
        let result_arena_header = FaultPayloadArenaHeader::new();
        let mut result_slots = vec![FaultResultSlotV1::new(); 4];
        let mut result_arena = vec![0_u8; 512];
        let event_ring = RingHeader::new();
        let event_arena_header = FaultPayloadArenaHeader::new();
        let mut event_slots = vec![FaultEventSlotV1::new(); 4];
        let mut event_arena = vec![0_u8; 512];
        let apis = QemuFaultCommandApis::test_stub();
        let capability_payload = encode_fault_capability_manifest(
            &apis
                .capability_rows()
                .unwrap_or_else(|error| panic!("test capabilities: {error}")),
        )
        .unwrap_or_else(|error| panic!("test manifest: {error}"));
        let mut bridge = FaultCommandBridge {
            apis,
            target_node_hash,
            commands: StableFaultCommandTransport {
                ring: NonNull::from(&command_ring),
                slots: NonNull::new(command_slots.as_mut_ptr())
                    .unwrap_or_else(|| panic!("test command slots must be non-empty")),
                slot_count: command_slots.len(),
                arena_header: NonNull::from(&command_arena_header),
                arena: NonNull::new(command_arena.as_mut_ptr())
                    .unwrap_or_else(|| panic!("test command arena must be non-empty")),
                arena_len: command_arena.len(),
                arena_region_offset: COMMAND_ARENA_OFFSET,
            },
            results: StableFaultResultTransport {
                ring: NonNull::from(&result_ring),
                slots: NonNull::new(result_slots.as_mut_ptr())
                    .unwrap_or_else(|| panic!("test result slots must be non-empty")),
                slot_count: result_slots.len(),
                arena_header: NonNull::from(&result_arena_header),
                arena: NonNull::new(result_arena.as_mut_ptr())
                    .unwrap_or_else(|| panic!("test result arena must be non-empty")),
                arena_len: result_arena.len(),
                arena_region_offset: RESULT_ARENA_OFFSET,
            },
            events: StableFaultEventTransport {
                ring: NonNull::from(&event_ring),
                slots: NonNull::new(event_slots.as_mut_ptr())
                    .unwrap_or_else(|| panic!("test event slots must be non-empty")),
                slot_count: event_slots.len(),
                arena_header: NonNull::from(&event_arena_header),
                arena: NonNull::new(event_arena.as_mut_ptr())
                    .unwrap_or_else(|| panic!("test event arena must be non-empty")),
                arena_len: event_arena.len(),
                arena_region_offset: EVENT_ARENA_OFFSET,
            },
            last_sequence: 0,
            capability_payload: capability_payload.clone(),
            capability_queries: BTreeSet::new(),
            register_manifest_payload: None,
            interrupt_manifest_payload: None,
            hardware_error_manifest_payload: None,
            clock_manifest_payload: None,
            accelerator_manifest_payload: None,
            system_manifest_payload: Vec::new(),
            register_evidence_identity: None,
            instruction_evidence_identity: None,
            register_commands: BTreeMap::new(),
            active_register_bindings: BTreeMap::new(),
            instruction_commands: BTreeMap::new(),
            active_instruction_bindings: BTreeMap::new(),
            exception_commands: BTreeMap::new(),
            memory_ecc_commands: BTreeMap::new(),
            clock_commands: BTreeMap::new(),
            active_clock_bindings: BTreeMap::new(),
            accelerator_commands: BTreeMap::new(),
            active_accelerator_bindings: BTreeMap::new(),
            pending_command: None,
        };
        let command = |kind, sequence, node_hash| FaultCommandHeaderV1 {
            abi_major: FAULT_COMMAND_ABI_MAJOR,
            abi_minor: FAULT_COMMAND_ABI_MINOR,
            command_kind: kind,
            command_flags: FAULT_COMMAND_FLAG_NONE,
            phase: FaultBoundaryPhase::NodeBoundary,
            semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
            command_sequence: sequence,
            target_node_hash: node_hash,
            target_icount: 50,
            authorization_ceiling_icount: 50,
            binding_hash: *blake3::hash(b"binding").as_bytes(),
            opportunity_hash: [0; 32],
            expected_precondition_hash: [0; 32],
            payload_hash: [0; 32],
            payload_offset: 0,
            payload_length: 0,
        };
        for header in [
            command(FaultCommandKind::QueryCapabilities, 1, target_node_hash),
            command(FaultCommandKind::BoundaryProbe, 2, [7; 32]),
            command(FaultCommandKind::BoundaryProbe, 2, target_node_hash),
        ] {
            enqueue_fault_command(
                &command_ring,
                &mut command_slots,
                &command_arena_header,
                &mut command_arena,
                COMMAND_ARENA_OFFSET,
                header,
                &[],
            )
            .unwrap_or_else(|error| panic!("enqueue test command: {error}"));
        }

        bridge
            .pump(40, 12)
            .unwrap_or_else(|error| panic!("pump test commands: {error}"));
        let results = (0..3)
            .map(|_index| {
                dequeue_fault_result(
                    &result_ring,
                    &result_slots,
                    &result_arena_header,
                    &result_arena,
                    RESULT_ARENA_OFFSET,
                )
                .unwrap_or_else(|error| panic!("dequeue test result: {error}"))
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            &results[0],
            Some(DequeuedFaultResult::Valid { header, payload })
                if header.status == FaultResultStatus::Applied
                    && header.observed_icount == 50
                    && header.applied_icount == 50
                    && header.evidence_hash == *blake3::hash(&capability_payload).as_bytes()
                    && payload == &capability_payload
        ));
        for (result, expected_status) in results[1..].iter().zip([
            FaultResultStatus::InvalidTarget,
            FaultResultStatus::DuplicateSequence,
        ]) {
            assert!(matches!(
                result,
                Some(DequeuedFaultResult::Valid { header, payload })
                    if header.status == expected_status
                        && header.observed_icount == 52
                        && header.applied_icount == 0
                        && payload.is_empty()
            ));
        }

        let pending_command = QemuFaultCommand {
            abi_major: FAULT_COMMAND_ABI_MAJOR,
            abi_minor: FAULT_COMMAND_ABI_MINOR,
            command_kind: FaultCommandKind::QueryCapabilities as u16,
            command_flags: FAULT_COMMAND_FLAG_NONE,
            phase: FaultBoundaryPhase::NodeBoundary as u16,
            reserved: 0,
            semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
            command_sequence: 99,
            target_node_hash,
            target_icount: 40,
            authorization_ceiling_icount: 40,
            binding_hash: [0; 32],
            opportunity_hash: [0; 32],
            expected_precondition_hash: [0; 32],
        };
        assert_eq!(test_submit(&pending_command, std::ptr::null(), 0), 0);
        for command_sequence in 10..14 {
            enqueue_fault_result(
                &result_ring,
                &mut result_slots,
                &result_arena_header,
                &mut result_arena,
                RESULT_ARENA_OFFSET,
                FaultResultHeaderV1 {
                    abi_major: FAULT_COMMAND_ABI_MAJOR,
                    abi_minor: FAULT_COMMAND_ABI_MINOR,
                    command_kind: FaultCommandKind::BoundaryProbe as u16,
                    status: FaultResultStatus::InvalidTarget,
                    semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
                    command_sequence,
                    observed_icount: 52,
                    applied_icount: 0,
                    capability_version: 1,
                    phase: FaultBoundaryPhase::NodeBoundary,
                    before_hash: [0; 32],
                    after_hash: [0; 32],
                    evidence_hash: [0; 32],
                    result_payload_hash: [0; 32],
                    result_offset: 0,
                    result_length: 0,
                },
                &[],
            )
            .unwrap_or_else(|error| panic!("fill result ring: {error}"));
        }

        bridge
            .pump(40, 12)
            .unwrap_or_else(|error| panic!("pump under backpressure: {error}"));
        TEST_CAPABILITY_RESULT_PENDING.with(|pending| assert!(pending.get().is_some()));
        let _released = dequeue_fault_result(
            &result_ring,
            &result_slots,
            &result_arena_header,
            &result_arena,
            RESULT_ARENA_OFFSET,
        )
        .unwrap_or_else(|error| panic!("release result capacity: {error}"));
        bridge
            .pump(40, 12)
            .unwrap_or_else(|error| panic!("pump after backpressure: {error}"));
        TEST_CAPABILITY_RESULT_PENDING.with(|pending| assert!(pending.get().is_none()));
        let mut saw_pending_result = false;
        while let Some(result) = dequeue_fault_result(
            &result_ring,
            &result_slots,
            &result_arena_header,
            &result_arena,
            RESULT_ARENA_OFFSET,
        )
        .unwrap_or_else(|error| panic!("drain result: {error}"))
        {
            if matches!(
                result,
                DequeuedFaultResult::Valid { header, .. } if header.command_sequence == 99
            ) {
                saw_pending_result = true;
            }
        }
        assert!(saw_pending_result);
    }

    #[test]
    fn register_evidence_binds_vcpu_and_terminal_cursor_phase() {
        use sha2::{Digest as _, Sha256};

        const HEADER: usize = 160;
        let before = [0_u8; 8];
        let mut after = before;
        after[0] = 1;
        let expected_before: [u8; 32] = Sha256::digest(before).into();
        let expected_after: [u8; 32] = Sha256::digest(after).into();
        let identity = RegisterEvidenceIdentity {
            architecture: FaultCapabilityScope::X86_64,
            manifest_digest: [1; 32],
            cpu_model_digest: [2; 32],
            rows: vec![FaultRegisterCapabilityRowV1 {
                numeric_id: 1,
                name: "rax".to_owned(),
                width_bits: 64,
                group: FaultRegisterGroupV1::GeneralPurpose,
                model_phase_mask: (1_u64 << 10) | (1_u64 << 11),
                side_effects: 0,
                capabilities: FAULT_REGISTER_CAPABILITY_IMPULSE
                    | crucible_shmem::FAULT_REGISTER_CAPABILITY_VMSTATE,
                writable_mask: vec![0xff; 8],
                reserved_mask: vec![0; 8],
                ignored_mask: vec![0; 8],
                read_only_mask: vec![0; 8],
            }],
        };
        let mut expectation = RegisterMutationExpectation {
            vcpu_index: 0,
            numeric_id: 1,
            model_phase: 12,
            mutation_kind: FaultRegisterMutationKindV1::BitFlip,
            first_bit: 0,
            bit_count: 1,
            mask: vec![1],
            value: vec![0],
        };
        let mut raw = vec![0_u8; HEADER + before.len() + after.len() + 2];
        raw[..8].copy_from_slice(b"CRUCQRW1");
        raw[8..10].copy_from_slice(&1_u16.to_le_bytes());
        raw[10..12].copy_from_slice(&(FaultCapabilityScope::X86_64 as u16).to_le_bytes());
        raw[12..14].copy_from_slice(&12_u16.to_le_bytes());
        raw[20..24].copy_from_slice(&1_u32.to_le_bytes());
        raw[24..28].copy_from_slice(&(FaultRegisterMutationKindV1::BitFlip as u32).to_le_bytes());
        raw[36..40].copy_from_slice(&0_u32.to_le_bytes());
        raw[40..44].copy_from_slice(&1_u32.to_le_bytes());
        raw[44..48].copy_from_slice(&8_u32.to_le_bytes());
        raw[48..52].copy_from_slice(&8_u32.to_le_bytes());
        raw[52..56].copy_from_slice(&1_u32.to_le_bytes());
        raw[56..64].copy_from_slice(&256_u64.to_le_bytes());
        raw[72..80].copy_from_slice(&256_u64.to_le_bytes());
        raw[80..88].copy_from_slice(&256_u64.to_le_bytes());
        raw[88..120].fill(3);
        raw[120..152].fill(4);
        raw[152..156].copy_from_slice(&1_u32.to_le_bytes());
        raw[HEADER..HEADER + before.len()].copy_from_slice(&before);
        raw[HEADER + before.len()..HEADER + before.len() + after.len()].copy_from_slice(&after);
        raw[HEADER + before.len() + after.len()] = 1;

        assert!(
            translate_register_evidence(
                &raw,
                &identity,
                0,
                256,
                Some(12),
                expected_before,
                expected_after,
                &expectation,
            )
            .is_ok()
        );

        raw[120..152].fill(3);
        assert!(matches!(
            translate_register_evidence(
                &raw,
                &identity,
                0,
                256,
                Some(12),
                expected_before,
                expected_after,
                &expectation,
            ),
            Err(FaultCommandBridgeError::RegisterEvidence)
        ));
        raw[120..152].fill(4);

        raw[88..120].fill(0);
        assert!(matches!(
            translate_register_evidence(
                &raw,
                &identity,
                0,
                256,
                Some(12),
                expected_before,
                expected_after,
                &expectation,
            ),
            Err(FaultCommandBridgeError::RegisterEvidence)
        ));
        raw[88..120].fill(3);

        raw[16..20].copy_from_slice(&1_u32.to_le_bytes());
        raw[64..72].copy_from_slice(&1_u64.to_le_bytes());
        assert!(matches!(
            translate_register_evidence(
                &raw,
                &identity,
                0,
                256,
                Some(12),
                expected_before,
                expected_after,
                &expectation,
            ),
            Err(FaultCommandBridgeError::RegisterEvidence)
        ));

        raw[16..20].fill(0);
        raw[64..72].fill(0);
        raw[12..14].copy_from_slice(&11_u16.to_le_bytes());
        expectation.model_phase = 11;
        assert!(matches!(
            translate_register_evidence(
                &raw,
                &identity,
                0,
                256,
                Some(11),
                expected_before,
                expected_after,
                &expectation,
            ),
            Err(FaultCommandBridgeError::RegisterEvidence)
        ));

        raw[12..14].copy_from_slice(&12_u16.to_le_bytes());
        raw[72..80].copy_from_slice(&257_u64.to_le_bytes());
        expectation.model_phase = 12;
        assert!(matches!(
            translate_register_evidence(
                &raw,
                &identity,
                0,
                256,
                Some(12),
                expected_before,
                expected_after,
                &expectation,
            ),
            Err(FaultCommandBridgeError::RegisterEvidence)
        ));
    }

    fn instruction_evidence_fixture() -> (
        Vec<u8>,
        InstructionEvidenceIdentity,
        RegisterEvidenceIdentity,
        QemuFaultEvent,
        InstructionCommandExpectation,
    ) {
        const HEADER: usize = 608;
        let instruction = [0x90_u8];
        let mut raw = vec![0_u8; HEADER + instruction.len()];
        raw[..8].copy_from_slice(b"CRUCINS1");
        raw[8..10].copy_from_slice(&3_u16.to_le_bytes());
        raw[10..12].copy_from_slice(&(FaultCapabilityScope::X86_64 as u16).to_le_bytes());
        raw[12..16].copy_from_slice(&(FaultInstructionMutationKindV1::Skip as u32).to_le_bytes());
        raw[24..28].copy_from_slice(&0x0100_0001_u32.to_le_bytes());
        raw[32..40].copy_from_slice(&0x1000_u64.to_le_bytes());
        raw[40..48].copy_from_slice(&0x2000_u64.to_le_bytes());
        raw[48..56].copy_from_slice(&17_u64.to_le_bytes());
        raw[56..60].copy_from_slice(&1_u32.to_le_bytes());
        raw[64..96].copy_from_slice(&sha2::Sha256::digest(instruction));
        raw[192..224].fill(3);
        raw[224..256].fill(4);
        raw[288..320].fill(5);
        raw[320..352].fill(6);
        raw[352..384].fill(7);
        raw[384..416].fill(8);
        raw[416..448].fill(1);
        raw[448..480].fill(2);
        raw[480..488].copy_from_slice(&4096_u64.to_le_bytes());
        raw[488..496].copy_from_slice(&4096_u64.to_le_bytes());
        raw[496..504].copy_from_slice(&128_u64.to_le_bytes());
        raw[504..512].copy_from_slice(&128_u64.to_le_bytes());
        let before_state = instruction_system_digest([1; 32], [5; 32], [7; 32], 4096, 128);
        let after_state = instruction_system_digest([2; 32], [6; 32], [8; 32], 4096, 128);
        raw[96..128].copy_from_slice(&before_state);
        raw[128..160].copy_from_slice(&after_state);
        raw[568..600].copy_from_slice(&before_state);
        raw[512..520].copy_from_slice(&0x2000_u64.to_le_bytes());
        raw[528..532].copy_from_slice(&1_u32.to_le_bytes());
        raw[HEADER] = instruction[0];
        let identity = InstructionEvidenceIdentity {
            architecture: FaultCapabilityScope::X86_64,
            manifest_sha256: [3; 32],
        };
        let register_identity = RegisterEvidenceIdentity {
            architecture: FaultCapabilityScope::X86_64,
            manifest_digest: [9; 32],
            cpu_model_digest: [10; 32],
            rows: Vec::new(),
        };
        let expectation = InstructionCommandExpectation {
            operation: NodeFaultOperationV1::Upsert,
            binding_hash: [12; 32],
            generation: 3,
            action_hash: [13; 32],
            target_hash: [14; 32],
            vcpu_index: 0,
            model_phase: 11,
            pc_start: 0x1000,
            pc_length: 1,
            instruction_bytes: Some(instruction.to_vec()),
            opcode_class: Some(0x0100_0001),
            input_state_sha256: None,
            mutation_kind: FaultInstructionMutationKindV1::Skip,
            replay_total: 0,
            next_replay_ordinal: 0,
            register_mutation: None,
        };
        let event = QemuFaultEvent {
            command_kind: FaultCommandKind::CpuInstructionTransform as u16,
            outcome: FaultEventOutcomeV1::Applied as u16,
            model_phase: 11,
            target_kind: NodeFaultTargetKindV1::Vcpu as u16,
            reserved: 0,
            event_sequence: 1,
            rule_command_sequence: 2,
            observed_icount: 17,
            generation: 3,
            binding_hash: [12; 32],
            opportunity_hash: sha2::Sha256::digest(&raw).into(),
            action_hash: [13; 32],
            target_hash: [14; 32],
            before_hash: before_state,
            after_hash: after_state,
        };
        (raw, identity, register_identity, event, expectation)
    }

    #[test]
    fn instruction_apply_terminal_results_retain_expectation_until_evidence_event() {
        let (_raw, _identity, _register_identity, event, mut expectation) =
            instruction_evidence_fixture();
        expectation.operation = NodeFaultOperationV1::Apply;
        for status in [FaultResultStatus::Applied, FaultResultStatus::InternalError] {
            let mut commands = BTreeMap::from([(event.rule_command_sequence, expectation.clone())]);
            let mut active_bindings = BTreeMap::new();

            track_instruction_result(
                &mut commands,
                &mut active_bindings,
                event.rule_command_sequence,
                status as u16,
            )
            .unwrap_or_else(|error| {
                panic!("terminal Apply result must remain correlatable: {error}")
            });

            assert!(commands.contains_key(&event.rule_command_sequence));
            assert!(active_bindings.is_empty());
            commands.remove(&event.rule_command_sequence);
            assert!(commands.is_empty());
        }
    }

    #[test]
    fn instruction_resource_terminal_translates_and_releases_correlation() {
        let (_raw, _identity, _register_identity, mut event, mut expectation) =
            instruction_evidence_fixture();
        let attempted_sha256 = [9_u8; 32];
        let mut terminal = [0_u8; crucible_shmem::FAULT_TERMINAL_EVIDENCE_V1_BYTES];

        terminal[..8].copy_from_slice(&crucible_shmem::FAULT_QUEUE_TERMINAL_EVIDENCE_MAGIC_V1);
        terminal[8..12].copy_from_slice(
            &(crucible_shmem::FaultTerminalReasonV1::EventCapacity as u32).to_le_bytes(),
        );
        terminal[12..16].copy_from_slice(&15_u32.to_le_bytes());
        terminal[16..20].copy_from_slice(&16_u32.to_le_bytes());
        terminal[20..22].copy_from_slice(&(FaultEventOutcomeV1::Applied as u16).to_le_bytes());
        terminal[24..32].copy_from_slice(&608_u64.to_le_bytes());
        terminal[32..64].copy_from_slice(&attempted_sha256);
        terminal[66..68].copy_from_slice(&1_u16.to_le_bytes());
        event.outcome = FaultEventOutcomeV1::Error as u16;
        event.opportunity_hash = attempted_sha256;
        expectation.operation = NodeFaultOperationV1::Apply;

        assert_eq!(
            translate_terminal_instruction_evidence(&terminal, &event, &expectation)
                .expect("correlated terminal evidence"),
            terminal
        );
        let mut commands = BTreeMap::from([(event.rule_command_sequence, expectation)]);
        let mut active_bindings = BTreeMap::new();
        track_terminal_instruction_event(
            &mut commands,
            &mut active_bindings,
            event.rule_command_sequence,
        )
        .expect("terminal event correlation");
        assert!(commands.is_empty());

        let mut wrong_hash = event;
        wrong_hash.opportunity_hash[0] ^= 1;
        let (_, _, _, _, expectation) = instruction_evidence_fixture();
        assert!(matches!(
            translate_terminal_instruction_evidence(&terminal, &wrong_hash, &expectation),
            Err(FaultCommandBridgeError::InstructionEvidence)
        ));
    }

    #[test]
    fn instruction_replay_events_require_exact_sequence_and_terminalize_once() {
        let (raw, identity, register_identity, event, mut expectation) =
            instruction_evidence_fixture();
        let canonical = translate_instruction_evidence(
            &raw,
            &identity,
            &register_identity,
            0,
            &event,
            &expectation,
        )
        .unwrap_or_else(|error| panic!("translate replay-sequence fixture: {error}"));
        let mut evidence = FaultInstructionEvidenceV1::decode(&canonical)
            .unwrap_or_else(|error| panic!("decode replay-sequence fixture: {error}"));
        evidence.mutation_kind = FaultInstructionMutationKindV1::Replay;
        evidence.replay_total = 2;
        expectation.operation = NodeFaultOperationV1::Apply;
        expectation.mutation_kind = FaultInstructionMutationKindV1::Replay;
        expectation.replay_total = 2;

        let mut commands = BTreeMap::from([(event.rule_command_sequence, expectation.clone())]);
        for ordinal in 0..=2 {
            evidence.replay_ordinal = ordinal;
            let payload = evidence
                .encode()
                .unwrap_or_else(|error| panic!("encode replay ordinal {ordinal}: {error}"));
            track_instruction_event(&mut commands, event.rule_command_sequence, &payload)
                .unwrap_or_else(|error| panic!("track replay ordinal {ordinal}: {error}"));
            assert_eq!(commands.is_empty(), ordinal == 2);
        }

        let mut commands = BTreeMap::from([(event.rule_command_sequence, expectation.clone())]);
        evidence.replay_ordinal = 1;
        let out_of_order = evidence
            .encode()
            .unwrap_or_else(|error| panic!("encode out-of-order replay: {error}"));
        assert!(matches!(
            track_instruction_event(&mut commands, event.rule_command_sequence, &out_of_order,),
            Err(FaultCommandBridgeError::InstructionEvidence)
        ));

        evidence.replay_ordinal = 0;
        evidence.outcome = FaultInstructionEvidenceOutcomeV1::Applied;
        let first = evidence
            .encode()
            .unwrap_or_else(|error| panic!("encode first replay event: {error}"));
        track_instruction_event(&mut commands, event.rule_command_sequence, &first)
            .unwrap_or_else(|error| panic!("track first replay event: {error}"));
        evidence.replay_ordinal = 1;
        evidence.outcome = FaultInstructionEvidenceOutcomeV1::Error;
        let error = evidence
            .encode()
            .unwrap_or_else(|error| panic!("encode fail-closed replay event: {error}"));
        track_instruction_event(&mut commands, event.rule_command_sequence, &error)
            .unwrap_or_else(|error| panic!("track fail-closed replay event: {error}"));
        assert!(commands.is_empty());
    }

    #[test]
    fn instruction_bridge_rejects_uncorrelated_private_evidence() {
        let (raw, identity, register_identity, event, expectation) = instruction_evidence_fixture();
        assert!(
            translate_instruction_evidence(
                &raw,
                &identity,
                &register_identity,
                5,
                &event,
                &expectation,
            )
            .is_ok()
        );

        for mutate in [(608_usize, 0xcc_u8), (24, 2), (416, 9)] {
            let mut malformed = raw.clone();
            malformed[mutate.0] = mutate.1;
            let mut correlated_event = event;
            correlated_event.opportunity_hash = sha2::Sha256::digest(&malformed).into();
            assert!(matches!(
                translate_instruction_evidence(
                    &malformed,
                    &identity,
                    &register_identity,
                    5,
                    &correlated_event,
                    &expectation,
                ),
                Err(FaultCommandBridgeError::InstructionEvidence)
            ));
        }

        let mut wrong_generation = event;
        wrong_generation.generation += 1;
        assert!(matches!(
            translate_instruction_evidence(
                &raw,
                &identity,
                &register_identity,
                5,
                &wrong_generation,
                &expectation,
            ),
            Err(FaultCommandBridgeError::InstructionEvidence)
        ));
    }

    #[test]
    fn instruction_bridge_requires_actual_device_io_for_device_replay() {
        let (mut raw, identity, register_identity, mut event, mut expectation) =
            instruction_evidence_fixture();
        let transcript = FaultInstructionPortIoEvidenceV1 {
            entries: vec![crucible_shmem::FaultInstructionPortIoEntryV1 {
                direction: crucible_shmem::FaultInstructionPortIoDirectionV1::Write,
                port: 0xe9,
                value: vec![b'X'],
                completed: true,
            }],
        }
        .encode()
        .expect("valid device-I/O transcript");
        raw[12..16].copy_from_slice(&(FaultInstructionMutationKindV1::Replay as u32).to_le_bytes());
        raw[20..24].copy_from_slice(&1_u32.to_le_bytes());
        raw[24..28].copy_from_slice(&0x0100_0008_u32.to_le_bytes());
        raw[28..32].copy_from_slice(&(1_u32 << 5).to_le_bytes());
        raw[60..64].copy_from_slice(&(transcript.len() as u32).to_le_bytes());
        raw[608] = 0xee;
        raw[64..96].copy_from_slice(&sha2::Sha256::digest([0xee]));
        raw.extend_from_slice(&transcript);
        event.opportunity_hash = sha2::Sha256::digest(&raw).into();
        expectation.instruction_bytes = Some(vec![0xee]);
        expectation.opcode_class = Some(0x0100_0008);
        expectation.mutation_kind = FaultInstructionMutationKindV1::Replay;
        expectation.replay_total = 1;

        let canonical = translate_instruction_evidence(
            &raw,
            &identity,
            &register_identity,
            5,
            &event,
            &expectation,
        )
        .expect("device replay with an authenticated transaction");
        let decoded = FaultInstructionEvidenceV1::decode(&canonical)
            .expect("canonical device-replay evidence");
        assert_eq!(
            FaultInstructionPortIoEvidenceV1::decode(&decoded.detail)
                .expect("canonical nested transcript")
                .entries[0]
                .port,
            0xe9
        );

        raw.truncate(609);
        raw[60..64].fill(0);
        event.opportunity_hash = sha2::Sha256::digest(&raw).into();
        assert!(matches!(
            translate_instruction_evidence(
                &raw,
                &identity,
                &register_identity,
                5,
                &event,
                &expectation,
            ),
            Err(FaultCommandBridgeError::InstructionEvidence)
        ));
    }

    fn exception_evidence_fixture() -> (
        Vec<u8>,
        InstructionEvidenceIdentity,
        QemuFaultEvent,
        ExceptionCommandExpectation,
    ) {
        let mut raw = vec![0_u8; 192];
        raw[..8].copy_from_slice(b"CRUCEXC1");
        raw[8..10].copy_from_slice(&2_u16.to_le_bytes());
        raw[10..12].copy_from_slice(&(FaultCapabilityScope::X86_64 as u16).to_le_bytes());
        raw[12..14].copy_from_slice(&2_u16.to_le_bytes());
        raw[20..24].copy_from_slice(&6_u32.to_le_bytes());
        raw[40..48].copy_from_slice(&10_u64.to_le_bytes());
        raw[49] = 1;
        raw[51] = 1;
        raw[56..64].copy_from_slice(&17_u64.to_le_bytes());
        raw[64..72].copy_from_slice(&0x3000_u64.to_le_bytes());
        raw[72..76].copy_from_slice(&6_u32.to_le_bytes());
        raw[96..128].fill(1);
        raw[128..160].fill(2);
        let identity = InstructionEvidenceIdentity {
            architecture: FaultCapabilityScope::X86_64,
            manifest_sha256: [3; 32],
        };
        let expectation = ExceptionCommandExpectation {
            binding_hash: [12; 32],
            generation: 4,
            action_hash: [13; 32],
            target_hash: [14; 32],
            architecture: FaultCapabilityScope::X86_64,
            model_phase: 2,
            vcpu_index: 0,
            vector: 6,
            syndrome: 0,
            fault_address: None,
            before_instruction: true,
            maskable: false,
            hardware_record: None,
        };
        let event = QemuFaultEvent {
            command_kind: FaultCommandKind::CpuException as u16,
            outcome: FaultEventOutcomeV1::Applied as u16,
            model_phase: 2,
            target_kind: NodeFaultTargetKindV1::Vcpu as u16,
            reserved: 0,
            event_sequence: 1,
            rule_command_sequence: 2,
            observed_icount: 17,
            generation: 4,
            binding_hash: [12; 32],
            opportunity_hash: sha2::Sha256::digest(&raw).into(),
            action_hash: [13; 32],
            target_hash: [14; 32],
            before_hash: [1; 32],
            after_hash: [2; 32],
        };
        (raw, identity, event, expectation)
    }

    #[test]
    fn exception_bridge_requires_proven_architectural_delivery() {
        let (raw, identity, event, expectation) = exception_evidence_fixture();
        assert!(translate_exception_evidence(&raw, &identity, 5, &event, &expectation).is_ok());

        let mut wrong_delivery = raw.clone();
        wrong_delivery[72] = 7;
        let mut correlated_event = event;
        correlated_event.opportunity_hash = sha2::Sha256::digest(&wrong_delivery).into();
        assert!(matches!(
            translate_exception_evidence(
                &wrong_delivery,
                &identity,
                5,
                &correlated_event,
                &expectation,
            ),
            Err(FaultCommandBridgeError::ExceptionEvidence)
        ));

        let mut not_applied = event;
        not_applied.outcome = FaultEventOutcomeV1::Suppressed as u16;
        assert!(matches!(
            translate_exception_evidence(&raw, &identity, 5, &not_applied, &expectation),
            Err(FaultCommandBridgeError::ExceptionEvidence)
        ));
    }

    #[test]
    fn hardware_exception_bridge_requires_manifest_identity_and_real_state_transition() {
        let status = (1_u64 << 63) | (1_u64 << 61);
        let global_status = 1_u64 << 2;
        let address = 0x1234_5000_u64;
        let row = FaultHardwareErrorCapabilityRowV1 {
            id: "x86.machine-check.recoverable".to_owned(),
            bank: "x86.mca.bank".to_owned(),
            channel: "x86.memory.channel".to_owned(),
            rank: "x86.memory.rank".to_owned(),
            firmware: "x86-mca".to_owned(),
            state: "x86-mca-bank-record-machine-check".to_owned(),
            record_kind: FaultHardwareErrorRecordKindV1::X86MachineCheck,
            error_class: FaultHardwareErrorClassV1::Recoverable,
            mechanism: FaultHardwareErrorMechanismV1::X86Mca,
            visibility_mask: crucible_shmem::FAULT_HARDWARE_ERROR_VISIBILITY_EXCEPTION,
            bank_number: 0,
            bank_count: 10,
            vector: 18,
            status_required: status,
            status_allowed: u64::MAX,
            syndrome_required: 0,
            syndrome_allowed: u32::MAX.into(),
            model_phase_mask: 1 << (11 - 1),
            privilege_mask: crucible_shmem::FAULT_HARDWARE_ERROR_PRIVILEGE_V1_MASK,
            corrected: false,
            maskable: false,
            vmstate: true,
        };
        let manifest = complete_x86_hardware_manifest(row.clone())
            .encode()
            .expect("valid x86 hardware manifest");
        let expectation = ExceptionCommandExpectation {
            binding_hash: [12; 32],
            generation: 4,
            action_hash: [13; 32],
            target_hash: [14; 32],
            architecture: FaultCapabilityScope::X86_64,
            model_phase: 11,
            vcpu_index: 0,
            vector: 18,
            syndrome: 0,
            fault_address: Some(address),
            before_instruction: true,
            maskable: false,
            hardware_record: Some(HardwareExceptionExpectation::X86MachineCheck {
                bank: 2,
                status,
                global_status,
                address: Some(address),
                misc: None,
                corrected: false,
            }),
        };
        let mut raw = vec![0_u8; 744];
        raw[..8].copy_from_slice(b"CRUCEXC1");
        raw[8..10].copy_from_slice(&2_u16.to_le_bytes());
        raw[10..12].copy_from_slice(&(FaultCapabilityScope::X86_64 as u16).to_le_bytes());
        raw[12..14].copy_from_slice(&11_u16.to_le_bytes());
        raw[20..24].copy_from_slice(&18_u32.to_le_bytes());
        raw[32..40].copy_from_slice(&address.to_le_bytes());
        raw[40..48].copy_from_slice(&10_u64.to_le_bytes());
        raw[48] = 1;
        raw[49] = 1;
        raw[51] = 2;
        raw[56..64].copy_from_slice(&17_u64.to_le_bytes());
        raw[72..76].copy_from_slice(&18_u32.to_le_bytes());
        raw[76] = 1;
        raw[88..96].copy_from_slice(&address.to_le_bytes());
        raw[96..128].fill(1);
        raw[128..160].fill(2);
        raw[160..162].copy_from_slice(&2_u16.to_le_bytes());
        raw[164..168].copy_from_slice(&2_u32.to_le_bytes());
        raw[168..176].copy_from_slice(&status.to_le_bytes());
        raw[176..184].copy_from_slice(&global_status.to_le_bytes());
        raw[184..192].copy_from_slice(&address.to_le_bytes());
        raw[201] = 1;
        raw[256..288].copy_from_slice(&crucible_shmem::fault_object_id_hash_v1(&row.id));
        raw[288..320].copy_from_slice(&crucible_shmem::fault_object_id_hash_v1(&row.bank));
        raw[320..352].copy_from_slice(&crucible_shmem::fault_object_id_hash_v1(&row.channel));
        raw[352..384].copy_from_slice(&crucible_shmem::fault_object_id_hash_v1(&row.rank));
        raw[384..388].copy_from_slice(&2_u32.to_le_bytes());
        for offset in [392_usize, 520] {
            raw[offset..offset + 8].copy_from_slice(b"CRUCHCS1");
            raw[offset + 8..offset + 12]
                .copy_from_slice(&(FaultCapabilityScope::X86_64 as u32).to_le_bytes());
            raw[offset + 12..offset + 16].copy_from_slice(&2_u32.to_le_bytes());
            raw[offset + 16..offset + 20].copy_from_slice(&2_u32.to_le_bytes());
        }
        raw[520 + 40..520 + 48].copy_from_slice(&status.to_le_bytes());
        raw[520 + 48..520 + 56].copy_from_slice(&address.to_le_bytes());
        raw[520 + 64..520 + 72].copy_from_slice(&global_status.to_le_bytes());
        raw[648..680].copy_from_slice(&sha2::Sha256::digest(&manifest));
        raw[680..712].copy_from_slice(&crucible_shmem::fault_object_id_hash_v1(&row.firmware));
        raw[712..744].copy_from_slice(&crucible_shmem::fault_object_id_hash_v1(&row.state));
        let event = QemuFaultEvent {
            command_kind: FaultCommandKind::CpuException as u16,
            outcome: FaultEventOutcomeV1::Applied as u16,
            model_phase: 11,
            target_kind: NodeFaultTargetKindV1::Vcpu as u16,
            reserved: 0,
            event_sequence: 1,
            rule_command_sequence: 2,
            observed_icount: 17,
            generation: 4,
            binding_hash: [12; 32],
            opportunity_hash: sha2::Sha256::digest(&raw).into(),
            action_hash: [13; 32],
            target_hash: [14; 32],
            before_hash: [1; 32],
            after_hash: [2; 32],
        };
        assert_eq!(
            translate_hardware_exception_evidence(&raw, &manifest, &event, &expectation),
            Ok(raw.clone())
        );

        let mut corrupt = raw;
        corrupt[520 + 40] ^= 1;
        let mut correlated = event;
        correlated.opportunity_hash = sha2::Sha256::digest(&corrupt).into();
        assert!(matches!(
            translate_hardware_exception_evidence(&corrupt, &manifest, &correlated, &expectation,),
            Err(FaultCommandBridgeError::HardwareErrorEvidence)
        ));
    }

    #[test]
    fn hardware_ecc_bridge_requires_exact_ghes_record_transition() {
        let address = 0x8123_4000_u64;
        let syndrome = 0x55aa_u64;
        let row = FaultHardwareErrorCapabilityRowV1 {
            id: "memory.ecc.corrected".to_owned(),
            bank: "memory.bank-0".to_owned(),
            channel: "memory.channel-0".to_owned(),
            rank: "memory.rank-0".to_owned(),
            firmware: "acpi-apei-ghes-sea".to_owned(),
            state: "acpi-ghes-cper-record".to_owned(),
            record_kind: FaultHardwareErrorRecordKindV1::MemoryEcc,
            error_class: FaultHardwareErrorClassV1::Corrected,
            mechanism: FaultHardwareErrorMechanismV1::AcpiGhes,
            visibility_mask: crucible_shmem::FAULT_HARDWARE_ERROR_VISIBILITY_TELEMETRY,
            bank_number: 0,
            bank_count: 1,
            vector: 3,
            status_required: 0,
            status_allowed: 0,
            syndrome_required: 0,
            syndrome_allowed: u64::MAX,
            model_phase_mask: 1 << (9 - 1),
            privilege_mask: crucible_shmem::FAULT_HARDWARE_ERROR_PRIVILEGE_V1_MASK,
            corrected: true,
            maskable: false,
            vmstate: true,
        };
        let manifest = complete_aarch64_hardware_manifest(row.clone())
            .encode()
            .expect("valid GHES manifest");
        let mut raw = vec![0_u8; 1376];
        raw[..8].copy_from_slice(b"CRUCHWE1");
        raw[8..10].copy_from_slice(&1_u16.to_le_bytes());
        raw[10..12].copy_from_slice(&(FaultCapabilityScope::Aarch64 as u16).to_le_bytes());
        raw[12..16].copy_from_slice(&4_u32.to_le_bytes());
        raw[16..24].copy_from_slice(&17_u64.to_le_bytes());
        raw[24..32].copy_from_slice(&address.to_le_bytes());
        raw[32..40].copy_from_slice(&syndrome.to_le_bytes());
        raw[40..48].copy_from_slice(&2_u64.to_le_bytes());
        raw[48] = 1;
        raw[64..96].copy_from_slice(&crucible_shmem::fault_object_id_hash_v1(&row.id));
        raw[96..128].copy_from_slice(&crucible_shmem::fault_object_id_hash_v1(&row.bank));
        raw[128..160].copy_from_slice(&crucible_shmem::fault_object_id_hash_v1(&row.channel));
        raw[160..192].copy_from_slice(&crucible_shmem::fault_object_id_hash_v1(&row.rank));
        raw[320..352].copy_from_slice(&sha2::Sha256::digest(&manifest));
        raw[352..384].copy_from_slice(&crucible_shmem::fault_object_id_hash_v1(&row.firmware));
        raw[384..416].copy_from_slice(&crucible_shmem::fault_object_id_hash_v1(&row.state));
        for offset in [416_usize, 544, 672] {
            raw[offset..offset + 8].copy_from_slice(b"CRUCHCS1");
        }
        for offset in [800_usize, 992, 1184] {
            raw[offset..offset + 8].copy_from_slice(b"CRUCGHS1");
            raw[offset + 16..offset + 20].copy_from_slice(&172_u32.to_le_bytes());
        }
        raw[800 + 8..800 + 16].copy_from_slice(&1_u64.to_le_bytes());
        for offset in [992_usize, 1184] {
            let record = offset + 20;
            raw[record..record + 4].copy_from_slice(&0x12_u32.to_le_bytes());
            raw[record + 12..record + 16].copy_from_slice(&152_u32.to_le_bytes());
            raw[record + 16..record + 20].copy_from_slice(&2_u32.to_le_bytes());
            raw[record + 20..record + 36].copy_from_slice(&[
                0x14, 0x11, 0xbc, 0xa5, 0x64, 0x6f, 0xde, 0x4e, 0xb8, 0x63, 0x3e, 0x83, 0xed, 0x7c,
                0x83, 0xb1,
            ]);
            raw[record + 36..record + 40].copy_from_slice(&2_u32.to_le_bytes());
            raw[record + 40..record + 42].copy_from_slice(&0x300_u16.to_le_bytes());
            raw[record + 44..record + 48].copy_from_slice(&80_u32.to_le_bytes());
            raw[record + 92..record + 100].copy_from_slice(&0xc052_u64.to_le_bytes());
            raw[record + 108..record + 116].copy_from_slice(&address.to_le_bytes());
        }
        let event = QemuFaultEvent {
            command_kind: FaultCommandKind::MemoryEccEvent as u16,
            outcome: FaultEventOutcomeV1::Applied as u16,
            model_phase: 9,
            target_kind: NodeFaultTargetKindV1::Memory as u16,
            reserved: 0,
            event_sequence: 1,
            rule_command_sequence: 2,
            observed_icount: 17,
            generation: 4,
            binding_hash: [12; 32],
            opportunity_hash: sha2::Sha256::digest(&raw).into(),
            action_hash: [13; 32],
            target_hash: [14; 32],
            before_hash: [1; 32],
            after_hash: [2; 32],
        };
        let expectation = MemoryEccCommandExpectation {
            binding_hash: [12; 32],
            generation: 4,
            action_hash: [13; 32],
            target_hash: [14; 32],
            model_phase: 9,
            target_vcpu: 0,
            kind: 1,
            address,
            syndrome,
            bank: crucible_shmem::fault_object_id_hash_v1(&row.bank),
            channel: crucible_shmem::fault_object_id_hash_v1(&row.channel),
            rank: crucible_shmem::fault_object_id_hash_v1(&row.rank),
            visibility: serde_json::json!({"kind": "telemetry_only"}),
        };
        assert_eq!(
            translate_hardware_ecc_evidence(&raw, &manifest, &event, &expectation),
            Ok(raw.clone())
        );

        let mut corrupt = raw;
        corrupt[992 + 128] ^= 1;
        let mut correlated = event;
        correlated.opportunity_hash = sha2::Sha256::digest(&corrupt).into();
        assert!(matches!(
            translate_hardware_ecc_evidence(&corrupt, &manifest, &correlated, &expectation),
            Err(FaultCommandBridgeError::HardwareErrorEvidence)
        ));
    }

    #[test]
    fn clock_timer_evidence_is_manifest_bound_and_typed() {
        let row = FaultClockCapabilityRowV1 {
            id: "arm-generic-counter-vcpu-0".to_owned(),
            implementation: "target/arm/generic-timer".to_owned(),
            source_kind: 7,
            base_domain: 1,
            timer_relationship: 1,
            width_bits: 64,
            flags: 0,
            frequency_numerator: 62_500_000,
            frequency_denominator: 1,
            model_phase_mask: (1_u64 << 27) | (1_u64 << 28) | (1_u64 << 29),
            vmstate: true,
            monotonicity: 2,
        };
        let manifest = FaultClockCapabilityManifestV1 {
            architecture: FaultCapabilityScope::Aarch64,
            rows: vec![row.clone()],
        }
        .encode()
        .unwrap_or_else(|error| panic!("clock manifest should encode: {error}"));
        let mut raw = vec![0_u8; 384];
        raw[..8].copy_from_slice(b"CRUCCTE1");
        raw[8..10].copy_from_slice(&1_u16.to_le_bytes());
        raw[10..12].copy_from_slice(&7_u16.to_le_bytes());
        raw[12..14].copy_from_slice(&1_u16.to_le_bytes());
        raw[16..20].copy_from_slice(&3_u32.to_le_bytes());
        raw[20..24].copy_from_slice(&1_u32.to_le_bytes());
        raw[24..32].copy_from_slice(&8_u64.to_le_bytes());
        raw[32..40].copy_from_slice(&100_u64.to_le_bytes());
        raw[40..48].copy_from_slice(&200_u64.to_le_bytes());
        raw[48..56].copy_from_slice(&4_u64.to_le_bytes());
        raw[56..64].copy_from_slice(&110_u64.to_le_bytes());
        raw[64..72].copy_from_slice(&210_u64.to_le_bytes());
        raw[72..80].copy_from_slice(&5_u64.to_le_bytes());
        raw[80..88].copy_from_slice(&5_u64.to_le_bytes());
        let source_id = crucible_shmem::fault_object_id_hash_v1(&row.id);
        raw[88..120].copy_from_slice(&source_id);
        raw[120..152].copy_from_slice(&[6; 32]);
        raw[152..184].copy_from_slice(&[7; 32]);
        raw[184..216].copy_from_slice(&[8; 32]);
        raw[216..224].copy_from_slice(&9_u64.to_le_bytes());
        raw[224..226].copy_from_slice(&30_u16.to_le_bytes());
        let arm_sequence = 2_u64;
        raw[240..248].copy_from_slice(
            &clock_timer_opportunity(source_id, arm_sequence, 30, 1, 3, 5).to_le_bytes(),
        );
        raw[248..256].copy_from_slice(&arm_sequence.to_le_bytes());
        let event = QemuFaultEvent {
            command_kind: FaultCommandKind::ClockTransform as u16,
            outcome: FaultEventOutcomeV1::Applied as u16,
            model_phase: 30,
            target_kind: NodeFaultTargetKindV1::Clock as u16,
            event_sequence: 1,
            rule_command_sequence: 2,
            observed_icount: 17,
            generation: 4,
            binding_hash: [6; 32],
            before_hash: [7; 32],
            after_hash: [8; 32],
            ..QemuFaultEvent::default()
        };
        let expectation = ClockCommandExpectation {
            operation: NodeFaultOperationV1::Upsert,
            command_kind: FaultCommandKind::ClockTransform as u16,
            binding_hash: [6; 32],
            model_phase: 30,
            source_ids: vec![source_id],
            parameters: ClockCommandParameters::Transform {
                kind: 1,
                signed_value: 1,
                ratio: [1, 1],
                unsigned_value: 0,
                process: None,
                monotonicity: 2,
                overdue_policy: 1,
            },
        };
        let encoded = translate_clock_evidence(&raw, &manifest, &event, 22, &expectation)
            .unwrap_or_else(|error| panic!("clock evidence should translate: {error}"));
        let decoded = FaultClockEvidenceV1::decode(&encoded)
            .unwrap_or_else(|error| panic!("clock evidence should decode: {error}"));
        assert_eq!(decoded.observed_icount, 22);
        assert!(matches!(
            decoded.observation,
            FaultClockObservationV1::TimerTransition { sequence: 8, .. }
        ));
        for offset in [224, 232, 240, 248] {
            let mut corrupt = raw.clone();
            corrupt[offset] ^= 1;
            assert!(matches!(
                translate_clock_evidence(&corrupt, &manifest, &event, 22, &expectation),
                Err(FaultCommandBridgeError::ClockEvidence)
            ));
        }
    }

    #[test]
    fn clock_impulse_result_and_event_use_the_same_typed_evidence() {
        let row = FaultClockCapabilityRowV1 {
            id: "x86-tsc-vcpu-0".to_owned(),
            implementation: "target/i386/tcg".to_owned(),
            source_kind: 1,
            base_domain: 1,
            timer_relationship: 0,
            width_bits: 64,
            flags: 1,
            frequency_numerator: 1_000_000_000,
            frequency_denominator: 1,
            model_phase_mask: (1_u64 << 27) | (1_u64 << 30) | (1_u64 << 31),
            vmstate: true,
            monotonicity: 2,
        };
        let manifest = FaultClockCapabilityManifestV1 {
            architecture: FaultCapabilityScope::X86_64,
            rows: vec![row.clone()],
        }
        .encode()
        .unwrap_or_else(|error| panic!("clock manifest should encode: {error}"));
        let source_id = crucible_shmem::fault_object_id_hash_v1(&row.id);
        let mut raw = vec![0_u8; 384];
        raw[..8].copy_from_slice(b"CRUCCIM1");
        raw[8..10].copy_from_slice(&1_u16.to_le_bytes());
        raw[10..12].copy_from_slice(&1_u16.to_le_bytes());
        raw[16..24].copy_from_slice(&17_u64.to_le_bytes());
        raw[24..32].copy_from_slice(&100_u64.to_le_bytes());
        raw[32..40].copy_from_slice(&101_u64.to_le_bytes());
        raw[40..48].copy_from_slice(&5_u64.to_le_bytes());
        raw[48..56].copy_from_slice(&1_u64.to_le_bytes());
        raw[56..64].copy_from_slice(&1_u64.to_le_bytes());
        raw[72..80].copy_from_slice(&5_u64.to_le_bytes());
        raw[80..112].copy_from_slice(&source_id);
        raw[112..144].copy_from_slice(&[6; 32]);
        raw[144..176].copy_from_slice(&[7; 32]);
        raw[176..208].copy_from_slice(&[8; 32]);
        raw[208..210].copy_from_slice(&29_u16.to_le_bytes());
        raw[210..212].copy_from_slice(&1_u16.to_le_bytes());
        raw[212..220].copy_from_slice(&100_u64.to_le_bytes());
        raw[220..228].copy_from_slice(&101_u64.to_le_bytes());
        raw[228..236].copy_from_slice(&1_u64.to_le_bytes());
        raw[236..244].copy_from_slice(&1_u64.to_le_bytes());
        raw[244..252].copy_from_slice(&5_u64.to_le_bytes());
        raw[264..268].copy_from_slice(&2_u32.to_le_bytes());
        raw[268..272].copy_from_slice(&1_u32.to_le_bytes());
        raw[272..276].copy_from_slice(&1_u32.to_le_bytes());
        let event = QemuFaultEvent {
            command_kind: FaultCommandKind::ClockTransform as u16,
            outcome: FaultEventOutcomeV1::Applied as u16,
            model_phase: 29,
            target_kind: NodeFaultTargetKindV1::Clock as u16,
            event_sequence: 1,
            rule_command_sequence: 2,
            observed_icount: 17,
            generation: 4,
            binding_hash: [6; 32],
            before_hash: [7; 32],
            after_hash: [8; 32],
            ..QemuFaultEvent::default()
        };
        let result = QemuFaultResult {
            command_kind: FaultCommandKind::ClockTransform as u16,
            status: FaultResultStatus::Applied as u16,
            phase: FaultBoundaryPhase::NodeBoundary as u16,
            command_sequence: 2,
            observed_icount: 17,
            applied_icount: 17,
            before_hash: [7; 32],
            after_hash: [8; 32],
            ..QemuFaultResult::default()
        };
        let expectation = ClockCommandExpectation {
            operation: NodeFaultOperationV1::Apply,
            command_kind: FaultCommandKind::ClockTransform as u16,
            binding_hash: [6; 32],
            model_phase: 29,
            source_ids: vec![source_id],
            parameters: ClockCommandParameters::Transform {
                kind: 1,
                signed_value: 5,
                ratio: [1, 1],
                unsigned_value: 0,
                process: None,
                monotonicity: 2,
                overdue_policy: 1,
            },
        };
        let from_event = translate_clock_evidence(&raw, &manifest, &event, 22, &expectation)
            .unwrap_or_else(|error| panic!("clock impulse event should translate: {error}"));
        let from_result =
            translate_clock_impulse_evidence(&raw, &manifest, &result, 5, &expectation)
                .unwrap_or_else(|error| panic!("clock impulse result should translate: {error}"));
        assert_eq!(from_event, from_result);
        let decoded = FaultClockEvidenceV1::decode(&from_event)
            .unwrap_or_else(|error| panic!("clock impulse should decode: {error}"));
        assert!(matches!(
            decoded.observation,
            FaultClockObservationV1::Impulse {
                transform_kind: 1,
                new_additive_nanos: 5,
                ..
            }
        ));
        let mut mismatched = expectation.clone();
        mismatched.parameters = ClockCommandParameters::Transform {
            kind: 1,
            signed_value: 6,
            ratio: [1, 1],
            unsigned_value: 0,
            process: None,
            monotonicity: 2,
            overdue_policy: 1,
        };
        assert!(matches!(
            translate_clock_evidence(&raw, &manifest, &event, 22, &mismatched),
            Err(FaultCommandBridgeError::ClockEvidence)
        ));
    }
}
