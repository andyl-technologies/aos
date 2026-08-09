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
    DequeuedFaultCommand, FAULT_CAPABILITY_FEATURE_REGISTER_MUTATION,
    FAULT_COMMAND_SEMANTIC_VERSION, FAULT_REGISTER_CAPABILITY_IMPULSE,
    FAULT_TARGET_MANIFEST_QUERY_V1_BYTES, FaultAbiError, FaultBoundaryPhase, FaultCapabilityRowV1,
    FaultCapabilityScope, FaultCommandHeaderV1, FaultCommandKind, FaultCommandSlotV1,
    FaultEventHeaderV1, FaultEventOutcomeV1, FaultEventSlotV1, FaultPayloadArenaHeader,
    FaultRegisterCapabilityManifestV1, FaultRegisterCapabilityRowV1, FaultRegisterGroupV1,
    FaultRegisterMutationEvidenceV1, FaultRegisterMutationKindV1, FaultResultHeaderV1,
    FaultResultSlotV1, FaultResultStatus, FaultTargetManifestKind, FaultTargetManifestQueryV1,
    FaultTransportError, HARD_FAULT_PAYLOAD_BYTES, MappedFaultCommandTransportMut,
    MappedFaultEventTransportMut, MappedFaultResultTransportMut, MappedSetupRegion,
    MappedSetupRegionAccessError, NodeFaultOperationV1, NodeFaultPayloadV1, RingHeader,
    can_enqueue_fault_event, can_enqueue_fault_result, dequeue_fault_command,
    encode_fault_capability_manifest, enqueue_fault_event, enqueue_fault_result,
    fault_capability_manifest_digest, fault_register_cpu_model_digest_v1,
    fault_register_manifest_digest_v1, node_fault_field,
};
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
const CAPABILITY_HASH_DOMAIN: &[u8] = b"crucible.qemu-fault-capability.v1\0";

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
        FaultRegisterCapabilityManifestV1::decode(
            &manifest
                .encode()
                .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })?,
        )
        .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })
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
        }
    }
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
struct RegisterMutationExpectation {
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
    register_evidence_identity: Option<RegisterEvidenceIdentity>,
    register_commands: BTreeMap<u64, RegisterCommandExpectation>,
    active_register_bindings: BTreeMap<[u8; 32], u64>,
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
            rows.push(target_manifest_capability_row(
                manifest.architecture,
                manifest_digest,
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
            (Some(payload), Some(evidence_identity))
        } else {
            (None, None)
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
            register_evidence_identity,
            register_commands: BTreeMap::new(),
            active_register_bindings: BTreeMap::new(),
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
                DequeuedFaultCommand::Valid { header, .. }
                    if header.command_kind == FaultCommandKind::QueryTargetManifest =>
                {
                    self.register_manifest_payload.as_ref().map_or(0, Vec::len)
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
            if query.kind != FaultTargetManifestKind::Register {
                return self.publish_local_rejection(
                    header.command_kind as u16,
                    header.command_sequence,
                    header.phase,
                    FaultResultStatus::UnsupportedCapability,
                    logical_icount,
                );
            }
            let Some(result_payload) = self.register_manifest_payload.clone() else {
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
            let published_payload_len =
                if peeked.command_kind == FaultCommandKind::CpuRegisterTransform as u16 {
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
                } else {
                    payload
                };
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

fn target_manifest_capability_row(
    architecture: FaultCapabilityScope,
    manifest_digest: [u8; 32],
) -> FaultCapabilityRowV1 {
    let name = b"qemu.target-manifest.register.v1";
    let schema = b"crucible.target-manifest-query.v1";
    let mut hasher = blake3::Hasher::new();
    hasher.update(CAPABILITY_HASH_DOMAIN);
    hasher.update(name);
    hasher.update(&[0]);
    hasher.update(schema);
    hasher.update(&[0]);
    hasher.update(&manifest_digest);
    FaultCapabilityRowV1 {
        command_kind: FaultCommandKind::QueryTargetManifest,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        scope: architecture,
        phase_mask: FaultBoundaryPhase::NodeBoundary.bit(),
        maximum_payload_bytes: FAULT_TARGET_MANIFEST_QUERY_V1_BYTES as u32,
        maximum_pending_commands: 1,
        required_feature_bits: FAULT_CAPABILITY_FEATURE_REGISTER_MUTATION,
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
    const HEADER: usize = 128;
    if raw.len() < HEADER
        || raw[..8] != *b"CRUCQRW1"
        || raw_u16(raw, 8)? != 1
        || raw[14..16] != [0, 0]
        || raw[124..128].iter().any(|byte| *byte != 0)
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
    let value_len = usize::try_from(raw_u32(raw, 120)?)
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
    if numeric_id != expectation.numeric_id
        || first_bit != expectation.first_bit
        || bit_count != expectation.bit_count
        || raw[mask_start..value_start] != expectation.mask
        || raw[value_start..] != expectation.value
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
        execution_fingerprint_sha256: raw[88..120]
            .try_into()
            .map_err(|_source| FaultCommandBridgeError::RegisterEvidence)?,
        before: raw[before_start..after_start].to_vec(),
        after: raw[after_start..mask_start].to_vec(),
        mask: raw[mask_start..value_start].to_vec(),
        value: raw[value_start..].to_vec(),
    };
    evidence
        .encode()
        .map_err(|_source| FaultCommandBridgeError::RegisterEvidence)
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
    /// Register mutation was advertised without its required capability row.
    #[error("QEMU register manifest has no CPU register-transform capability")]
    RegisterCapabilityMissing,
    /// QEMU returned malformed or identity-inconsistent register evidence.
    #[error("QEMU register mutation evidence is invalid")]
    RegisterEvidence,
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
            register_evidence_identity: None,
            register_commands: BTreeMap::new(),
            active_register_bindings: BTreeMap::new(),
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
}
