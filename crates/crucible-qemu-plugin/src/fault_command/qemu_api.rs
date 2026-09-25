//! QEMU fault-command ABI resolution and immutable capability manifests.

use super::*;

mod manifests;

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct QemuFaultCommand {
    pub(super) abi_major: u16,
    pub(super) abi_minor: u16,
    pub(super) command_kind: u16,
    pub(super) command_flags: u16,
    pub(super) phase: u16,
    pub(super) reserved: u16,
    pub(super) semantic_version: u32,
    pub(super) command_sequence: u64,
    pub(super) target_node_hash: [u8; 32],
    pub(super) target_icount: u64,
    pub(super) authorization_ceiling_icount: u64,
    pub(super) binding_hash: [u8; 32],
    pub(super) opportunity_hash: [u8; 32],
    pub(super) expected_precondition_hash: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct QemuFaultResult {
    pub(super) command_kind: u16,
    pub(super) status: u16,
    pub(super) phase: u16,
    pub(super) reserved: u16,
    pub(super) semantic_version: u32,
    pub(super) capability_version: u32,
    pub(super) command_sequence: u64,
    pub(super) observed_icount: u64,
    pub(super) applied_icount: u64,
    /// Exact QEMU simulated tick captured when this result entered the queue.
    pub(super) emitted_tick: u64,
    pub(super) before_hash: [u8; 32],
    pub(super) after_hash: [u8; 32],
    pub(super) evidence_hash: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct QemuFaultEvent {
    pub(super) command_kind: u16,
    pub(super) outcome: u16,
    pub(super) model_phase: u16,
    pub(super) target_kind: u16,
    pub(super) evidence_length: u32,
    pub(super) event_sequence: u64,
    pub(super) rule_command_sequence: u64,
    pub(super) observed_icount: u64,
    /// Exact QEMU simulated tick captured when this event entered the queue.
    pub(super) observed_tick: u64,
    pub(super) generation: u64,
    pub(super) binding_hash: [u8; 32],
    pub(super) opportunity_hash: [u8; 32],
    pub(super) action_hash: [u8; 32],
    pub(super) target_hash: [u8; 32],
    pub(super) before_hash: [u8; 32],
    pub(super) after_hash: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct QemuFaultCapability {
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
pub(super) struct QemuFaultRegisterCapability {
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
pub(super) struct QemuFaultInterruptCapability {
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
pub(super) struct QemuFaultHardwareErrorCapability {
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
pub(super) struct QemuFaultClockCapability {
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
pub(super) struct QemuFaultAcceleratorCapability {
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
pub(super) struct QemuFaultSystemManifest {
    semantic_version: u32,
    vmstate_format_version: u32,
    vmstate_section_count: u32,
    reserved: u32,
    vmstate_sections_sha256: [u8; 32],
    system_capability: *const c_char,
    vmstate_capability: *const c_char,
    qemu_build_id: *const c_char,
    qemu_atomic_patch_hash: *const c_char,
    shmem_header_hash: *const c_char,
}

pub(super) type QemuFaultCapabilitiesFn = extern "C" fn(*mut QemuFaultCapability, usize) -> usize;
pub(super) type QemuFaultSubmitFn =
    extern "C" fn(*const QemuFaultCommand, *const u8, usize) -> c_int;
pub(super) type QemuFaultPeekFn = extern "C" fn(*mut QemuFaultResult, *mut usize) -> c_int;
pub(super) type QemuFaultPollFn =
    extern "C" fn(*mut QemuFaultResult, *mut u8, usize, *mut usize) -> c_int;
pub(super) type QemuFaultEventPeekFn = extern "C" fn(*mut QemuFaultEvent, *mut usize) -> c_int;
pub(super) type QemuFaultEventEnvelopeVersionFn = extern "C" fn() -> c_int;
pub(super) type QemuFaultEventPollFn =
    extern "C" fn(*mut QemuFaultEvent, *mut u8, usize, *mut usize) -> c_int;
pub(super) type QemuFaultRegisterManifestFn =
    extern "C" fn(*mut QemuFaultRegisterCapability, usize, *mut u16, *mut *const c_char) -> usize;
pub(super) type QemuFaultRegisterBindFn = extern "C" fn(*const u8, u32) -> c_int;
pub(super) type QemuFaultRegisterBindArchitectureFn = extern "C" fn(*const u8) -> c_int;
pub(super) type QemuFaultRegisterBindingsSealFn = extern "C" fn() -> c_int;
pub(super) type QemuFaultInstructionManifestFn =
    extern "C" fn(*mut u8, usize, *mut u8, *mut u16) -> usize;
pub(super) type QemuFaultInterruptManifestFn =
    extern "C" fn(*mut QemuFaultInterruptCapability, usize, *mut u16) -> usize;
pub(super) type QemuFaultInterruptBindFn =
    extern "C" fn(u32, *const u8, *const u8, *const u8) -> c_int;
pub(super) type QemuFaultInterruptBindingsSealFn = extern "C" fn() -> c_int;
pub(super) type QemuFaultHardwareErrorManifestFn =
    extern "C" fn(*mut QemuFaultHardwareErrorCapability, usize, *mut u16) -> usize;
pub(super) type QemuFaultHardwareErrorBindFn =
    extern "C" fn(u32, *const u8, *const u8, *const u8, *const u8, *const u8, *const u8) -> c_int;
pub(super) type QemuFaultHardwareErrorBindingsSealFn = extern "C" fn(*const u8) -> c_int;
pub(super) type QemuFaultClockManifestFn =
    extern "C" fn(*mut QemuFaultClockCapability, usize, *mut u16) -> usize;
pub(super) type QemuFaultClockBindFn = extern "C" fn(u32, *const u8) -> c_int;
pub(super) type QemuFaultClockBindingsSealFn = extern "C" fn(*const u8) -> c_int;
pub(super) type QemuFaultAcceleratorManifestFn =
    extern "C" fn(*mut QemuFaultAcceleratorCapability, usize) -> usize;
pub(super) type QemuFaultSystemManifestFn = extern "C" fn(*mut QemuFaultSystemManifest) -> c_int;
pub(super) type QemuFaultDispatchNodeBoundaryFn = extern "C" fn(u64) -> c_int;

/// Resolved, closed QEMU fault registry operations.
#[derive(Clone, Copy)]
pub(crate) struct QemuFaultCommandApis {
    pub(super) capabilities: QemuFaultCapabilitiesFn,
    pub(super) submit: QemuFaultSubmitFn,
    pub(super) peek: QemuFaultPeekFn,
    pub(super) poll: QemuFaultPollFn,
    pub(super) event_peek: QemuFaultEventPeekFn,
    pub(super) event_envelope_version: QemuFaultEventEnvelopeVersionFn,
    pub(super) event_poll: QemuFaultEventPollFn,
    pub(super) register_manifest: QemuFaultRegisterManifestFn,
    pub(super) register_bind: QemuFaultRegisterBindFn,
    pub(super) register_bind_architecture: QemuFaultRegisterBindArchitectureFn,
    pub(super) register_bindings_seal: QemuFaultRegisterBindingsSealFn,
    pub(super) instruction_manifest: QemuFaultInstructionManifestFn,
    pub(super) interrupt_manifest: QemuFaultInterruptManifestFn,
    pub(super) interrupt_bind: QemuFaultInterruptBindFn,
    pub(super) interrupt_bindings_seal: QemuFaultInterruptBindingsSealFn,
    pub(super) hardware_error_manifest: QemuFaultHardwareErrorManifestFn,
    pub(super) hardware_error_bind: QemuFaultHardwareErrorBindFn,
    pub(super) hardware_error_bindings_seal: QemuFaultHardwareErrorBindingsSealFn,
    pub(super) clock_manifest: QemuFaultClockManifestFn,
    pub(super) clock_bind: QemuFaultClockBindFn,
    pub(super) clock_bindings_seal: QemuFaultClockBindingsSealFn,
    pub(super) accelerator_manifest: QemuFaultAcceleratorManifestFn,
    pub(super) system_manifest: QemuFaultSystemManifestFn,
    pub(super) dispatch_node_boundary: QemuFaultDispatchNodeBoundaryFn,
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
            dispatch_node_boundary: resolve_symbol(
                DISPATCH_NODE_BOUNDARY_SYMBOL_C,
                QEMU_PLUGIN_CRUCIBLE_FAULT_DISPATCH_NODE_BOUNDARY_SYMBOL,
            )?,
        })
    }

    #[cfg(not(unix))]
    pub(crate) const fn resolve() -> Result<Self, FaultCommandBridgeError> {
        Err(FaultCommandBridgeError::CapabilityUnavailable {
            symbol: QEMU_PLUGIN_CRUCIBLE_FAULT_CAPABILITIES_SYMBOL,
        })
    }

    #[cfg(test)]
    pub(crate) const fn test_stub() -> Self {
        Self {
            capabilities: test_capabilities,
            submit: test_submit,
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
            dispatch_node_boundary: test_dispatch_node_boundary,
        }
    }
}

#[cfg(test)]
extern "C" fn test_dispatch_node_boundary(_raw_icount: u64) -> c_int {
    TEST_DISPATCH_RESULT_PENDING.with(|staged| {
        if let Some((commands, capture_seed)) = staged.take() {
            TEST_DISPATCH_RESULTS.with(|results| {
                results.borrow_mut().extend(commands);
            });
            crate::runtime::live_callbacks::tests::TEST_FINGERPRINT_CAPTURE_SEED
                .with(|seed| seed.set(capture_seed.into()));
        }
    });
    test_support::activate_staged_dispatch_event();
    0
}

#[cfg(test)]
extern "C" fn test_system_manifest(_out: *mut QemuFaultSystemManifest) -> c_int {
    static CAPABILITY: &[u8] = b"qemu.fault-system.complete.v1\0";
    static VMSTATE: &[u8] = b"qemu.fault-vmstate.v1\0";
    static BUILD_ID: std::sync::OnceLock<std::ffi::CString> = std::sync::OnceLock::new();
    static ATOMIC_PATCH_HASH: std::sync::OnceLock<std::ffi::CString> = std::sync::OnceLock::new();
    static SHMEM_HEADER_HASH: std::sync::OnceLock<std::ffi::CString> = std::sync::OnceLock::new();
    if _out.is_null() {
        return -libc::EINVAL;
    }
    let build_id = test_system_identity(&BUILD_ID, EXPECTED_QEMU_BUILD_ID);
    let atomic_patch_hash =
        test_system_identity(&ATOMIC_PATCH_HASH, EXPECTED_QEMU_ATOMIC_PATCH_HASH);
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
            qemu_atomic_patch_hash: atomic_patch_hash.as_ptr(),
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
pub(super) extern "C" fn test_submit(
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
extern "C" fn test_peek(result: *mut QemuFaultResult, payload_length: *mut usize) -> c_int {
    if result.is_null() || payload_length.is_null() {
        return -libc::EINVAL;
    }
    let command = TEST_CAPABILITY_RESULT_PENDING
        .with(|pending| pending.get())
        .or_else(|| TEST_DISPATCH_RESULTS.with(|results| results.borrow().front().copied()));
    let Some(command) = command else {
        return 0;
    };
    // SAFETY: the bridge supplies complete writable output objects for
    // this synchronous, non-consuming ABI call.
    unsafe {
        *payload_length = 0;
        *result = test_result_for_command(command);
    }
    1
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
    let command = TEST_CAPABILITY_RESULT_PENDING
        .with(|pending| pending.take())
        .or_else(|| TEST_DISPATCH_RESULTS.with(|results| results.borrow_mut().pop_front()));
    let Some(command) = command else {
        return 0;
    };
    // SAFETY: the bridge supplies one complete writable result object for
    // this synchronous ABI call.
    unsafe {
        *payload_length = 0;
        *result = test_result_for_command(command);
    }
    1
}

#[cfg(test)]
extern "C" fn test_event_envelope_version() -> c_int {
    1
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
    pub(super) static TEST_CAPABILITY_RESULT_PENDING: std::cell::Cell<Option<QemuFaultCommand>> =
        const { std::cell::Cell::new(None) };
    pub(super) static TEST_DISPATCH_RESULT_PENDING: std::cell::RefCell<Option<(Vec<QemuFaultCommand>, u8)>> =
        const { std::cell::RefCell::new(None) };
    pub(super) static TEST_DISPATCH_RESULTS: std::cell::RefCell<std::collections::VecDeque<QemuFaultCommand>> =
        const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
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
