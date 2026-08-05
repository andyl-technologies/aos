//! Live shared-memory to QEMU fault-command bridge.
//!
//! The Apache host publishes only the dual-licensed byte protocol. This GPL
//! module validates and copies that protocol, translates scheduler-logical
//! instruction coordinates to QEMU's raw retired-instruction space, and calls
//! the closed QEMU fault registry through resolved C symbols. Results take the
//! reverse path and are re-encoded into the public shared-memory ABI.

use std::collections::BTreeSet;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr::NonNull;

use crucible_shmem::{
    DequeuedFaultCommand, FaultAbiError, FaultBoundaryPhase, FaultCapabilityRowV1,
    FaultCommandHeaderV1, FaultCommandKind, FaultCommandSlotV1, FaultPayloadArenaHeader,
    FaultResultHeaderV1, FaultResultSlotV1, FaultResultStatus, FaultTransportError,
    HARD_FAULT_PAYLOAD_BYTES, MappedFaultCommandTransportMut, MappedFaultResultTransportMut,
    MappedSetupRegion, MappedSetupRegionAccessError, RingHeader, dequeue_fault_command,
    encode_fault_capability_manifest, enqueue_fault_result, fault_capability_manifest_digest,
};
use thiserror::Error;

/// QEMU symbol that copies the immutable sorted fault capability registry.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_CAPABILITIES_SYMBOL: &str =
    "qemu_plugin_crucible_fault_capabilities";
/// QEMU symbol that copies and arms one validated fault command.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_SUBMIT_SYMBOL: &str = "qemu_plugin_crucible_fault_submit";
/// QEMU symbol that cancels one not-yet-applied command.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_CANCEL_SYMBOL: &str = "qemu_plugin_crucible_fault_cancel";
/// QEMU symbol that copies one completed fault result.
pub const QEMU_PLUGIN_CRUCIBLE_FAULT_POLL_SYMBOL: &str = "qemu_plugin_crucible_fault_poll";

const CAPABILITIES_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_fault_capabilities\0";
const SUBMIT_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_fault_submit\0";
const CANCEL_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_fault_cancel\0";
const POLL_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_fault_poll\0";
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
#[derive(Clone, Copy, Default)]
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

type QemuFaultCapabilitiesFn = extern "C" fn(*mut QemuFaultCapability, usize) -> usize;
type QemuFaultSubmitFn = extern "C" fn(*const QemuFaultCommand, *const u8, usize) -> c_int;
type QemuFaultCancelFn = extern "C" fn(u64) -> c_int;
type QemuFaultPollFn = extern "C" fn(*mut QemuFaultResult, *mut u8, usize, *mut usize) -> c_int;

/// Resolved, closed QEMU fault registry operations.
#[derive(Clone, Copy)]
pub(crate) struct QemuFaultCommandApis {
    capabilities: QemuFaultCapabilitiesFn,
    submit: QemuFaultSubmitFn,
    #[allow(dead_code, reason = "cancellation is used by restore rollback wiring")]
    cancel: QemuFaultCancelFn,
    poll: QemuFaultPollFn,
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
            poll: resolve_symbol(POLL_SYMBOL_C, QEMU_PLUGIN_CRUCIBLE_FAULT_POLL_SYMBOL)?,
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

    #[cfg(test)]
    pub(crate) const fn test_stub() -> Self {
        Self {
            capabilities: test_capabilities,
            submit: test_submit,
            cancel: test_cancel,
            poll: test_poll,
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
            *result = QemuFaultResult {
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
            };
        }
        1
    })
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
        scope: raw.scope,
        phase_mask: raw.phase_mask,
        maximum_payload_bytes: raw.maximum_payload_bytes,
        maximum_pending_commands: raw.maximum_pending_commands,
        required_feature_bits: raw.required_feature_bits,
        capability_hash: *hasher.finalize().as_bytes(),
    };
    FaultCapabilityRowV1::decode(&row.encode())
        .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })
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
}

/// Live bridge for one VM's bounded command and result transports.
pub(crate) struct FaultCommandBridge {
    apis: QemuFaultCommandApis,
    target_node_hash: [u8; 32],
    commands: StableFaultCommandTransport,
    results: StableFaultResultTransport,
    last_sequence: u64,
    capability_payload: Vec<u8>,
    capability_queries: BTreeSet<u64>,
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
        let rows = apis.capability_rows()?;
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
        Ok(Self {
            apis,
            target_node_hash,
            commands,
            results,
            last_sequence: 0,
            capability_payload,
            capability_queries: BTreeSet::new(),
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
        self.poll_results(logical_icount_offset)?;
        while let Some(command) = self.commands.dequeue()? {
            match command {
                DequeuedFaultCommand::Valid { header, payload } => {
                    self.submit(header, &payload, logical_icount_offset, logical_icount)?;
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
            self.poll_results(logical_icount_offset)?;
        }
        self.poll_results(logical_icount_offset)
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
        Ok(())
    }

    fn poll_results(&mut self, logical_icount_offset: u64) -> Result<(), FaultCommandBridgeError> {
        let payload_capacity = usize::try_from(HARD_FAULT_PAYLOAD_BYTES)
            .map_err(|_source| FaultCommandBridgeError::PayloadCapacity)?;
        let mut payload = vec![0_u8; payload_capacity];
        loop {
            let mut result = QemuFaultResult::default();
            let mut payload_len = 0_usize;
            let status = (self.apis.poll)(
                &mut result,
                payload.as_mut_ptr(),
                payload.len(),
                &mut payload_len,
            );
            if status == 0 {
                return Ok(());
            }
            if status != 1 {
                return Err(FaultCommandBridgeError::QemuPoll { status });
            }
            if payload_len > payload.len() {
                return Err(FaultCommandBridgeError::QemuPayloadLength {
                    length: payload_len,
                    capacity: payload.len(),
                });
            }
            let mut result_payload = &payload[..payload_len];
            let query_payload;
            if self.capability_queries.remove(&result.command_sequence)
                && result.status == FaultResultStatus::Applied as u16
            {
                query_payload = self.capability_payload.clone();
                result_payload = &query_payload;
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
        _ => Err(FaultCommandBridgeError::QemuStatus { value }),
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
    /// QEMU claimed a result larger than the hard buffer.
    #[error("QEMU fault result payload length {length} exceeds buffer {capacity}")]
    QemuPayloadLength {
        /// Returned length.
        length: usize,
        /// Available bytes.
        capacity: usize,
    },
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
    fn bridge_translates_capabilities_and_local_rejections_at_logical_time() {
        const COMMAND_ARENA_OFFSET: u64 = 4_096;
        const RESULT_ARENA_OFFSET: u64 = 8_192;
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
            last_sequence: 0,
            capability_payload: capability_payload.clone(),
            capability_queries: BTreeSet::new(),
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
    }
}
