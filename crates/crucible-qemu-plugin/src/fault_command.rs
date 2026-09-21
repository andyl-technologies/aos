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
const QEMU_PLUGIN_CRUCIBLE_FAULT_CAPABILITIES_SYMBOL: &str =
    "qemu_plugin_crucible_fault_capabilities";
/// QEMU symbol that copies and arms one validated fault command.
const QEMU_PLUGIN_CRUCIBLE_FAULT_SUBMIT_SYMBOL: &str = "qemu_plugin_crucible_fault_submit";
/// QEMU symbol that non-destructively describes the oldest completed result.
const QEMU_PLUGIN_CRUCIBLE_FAULT_PEEK_SYMBOL: &str = "qemu_plugin_crucible_fault_peek";
/// QEMU symbol that copies one completed fault result.
const QEMU_PLUGIN_CRUCIBLE_FAULT_POLL_SYMBOL: &str = "qemu_plugin_crucible_fault_poll";
/// QEMU symbol that non-destructively describes the oldest rule event.
const QEMU_PLUGIN_CRUCIBLE_FAULT_EVENT_PEEK_SYMBOL: &str = "qemu_plugin_crucible_fault_event_peek";
/// QEMU symbol that reports the mandatory restored-event envelope schema.
const QEMU_PLUGIN_CRUCIBLE_FAULT_EVENT_ENVELOPE_VERSION_SYMBOL: &str =
    "qemu_plugin_crucible_fault_event_envelope_version";
/// QEMU symbol that copies and consumes one rule event.
const QEMU_PLUGIN_CRUCIBLE_FAULT_EVENT_POLL_SYMBOL: &str = "qemu_plugin_crucible_fault_event_poll";
/// QEMU symbol that copies architecture-owned register target rows.
const QEMU_PLUGIN_CRUCIBLE_FAULT_REGISTER_MANIFEST_SYMBOL: &str =
    "qemu_plugin_crucible_fault_register_manifest";
/// QEMU symbol that seals one public identity-to-private-register binding.
const QEMU_PLUGIN_CRUCIBLE_FAULT_REGISTER_BIND_SYMBOL: &str =
    "qemu_plugin_crucible_fault_register_bind";
/// QEMU symbol that binds the public register architecture identity.
const QEMU_PLUGIN_CRUCIBLE_FAULT_REGISTER_BIND_ARCHITECTURE_SYMBOL: &str =
    "qemu_plugin_crucible_fault_register_bind_architecture";
/// QEMU symbol that seals the complete register identity map.
const QEMU_PLUGIN_CRUCIBLE_FAULT_REGISTER_BINDINGS_SEAL_SYMBOL: &str =
    "qemu_plugin_crucible_fault_register_bindings_seal";
/// QEMU symbol that copies the immutable instruction decoder manifest.
const QEMU_PLUGIN_CRUCIBLE_FAULT_INSTRUCTION_MANIFEST_SYMBOL: &str =
    "qemu_plugin_crucible_fault_instruction_manifest";
/// QEMU symbol that copies architecture-owned interrupt target rows.
const QEMU_PLUGIN_CRUCIBLE_FAULT_INTERRUPT_MANIFEST_SYMBOL: &str =
    "qemu_plugin_crucible_fault_interrupt_manifest";
/// QEMU symbol that binds one public interrupt identity row.
const QEMU_PLUGIN_CRUCIBLE_FAULT_INTERRUPT_BIND_SYMBOL: &str =
    "qemu_plugin_crucible_fault_interrupt_bind";
/// QEMU symbol that seals every interrupt identity row.
const QEMU_PLUGIN_CRUCIBLE_FAULT_INTERRUPT_BINDINGS_SEAL_SYMBOL: &str =
    "qemu_plugin_crucible_fault_interrupt_bindings_seal";
/// QEMU symbol that copies architecture and platform hardware-error rows.
const QEMU_PLUGIN_CRUCIBLE_FAULT_HARDWARE_ERROR_MANIFEST_SYMBOL: &str =
    "qemu_plugin_crucible_fault_hardware_error_manifest";
/// QEMU symbol that binds one public hardware-error identity row.
const QEMU_PLUGIN_CRUCIBLE_FAULT_HARDWARE_ERROR_BIND_SYMBOL: &str =
    "qemu_plugin_crucible_fault_hardware_error_bind";
/// QEMU symbol that seals every hardware-error identity row.
const QEMU_PLUGIN_CRUCIBLE_FAULT_HARDWARE_ERROR_BINDINGS_SEAL_SYMBOL: &str =
    "qemu_plugin_crucible_fault_hardware_error_bindings_seal";
/// QEMU symbol that copies realized guest-clock source rows.
const QEMU_PLUGIN_CRUCIBLE_FAULT_CLOCK_MANIFEST_SYMBOL: &str =
    "qemu_plugin_crucible_fault_clock_manifest";
/// QEMU symbol that binds one guest-clock source identity.
const QEMU_PLUGIN_CRUCIBLE_FAULT_CLOCK_BIND_SYMBOL: &str = "qemu_plugin_crucible_fault_clock_bind";
/// QEMU symbol that seals every guest-clock source identity.
const QEMU_PLUGIN_CRUCIBLE_FAULT_CLOCK_BINDINGS_SEAL_SYMBOL: &str =
    "qemu_plugin_crucible_fault_clock_bindings_seal";
/// QEMU symbol that copies realized accelerator-device rows.
const QEMU_PLUGIN_CRUCIBLE_FAULT_ACCELERATOR_MANIFEST_SYMBOL: &str =
    "qemu_plugin_crucible_fault_accelerator_manifest";
/// QEMU symbol that returns the final build, patch, shmem, and VMState identity.
const QEMU_PLUGIN_CRUCIBLE_FAULT_SYSTEM_MANIFEST_SYMBOL: &str =
    "qemu_plugin_crucible_fault_system_manifest";
/// QEMU symbol that synchronously commits due node-boundary fault mutations.
const QEMU_PLUGIN_CRUCIBLE_FAULT_DISPATCH_NODE_BOUNDARY_SYMBOL: &str =
    "qemu_plugin_crucible_fault_dispatch_node_boundary";

const CAPABILITIES_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_fault_capabilities\0";
const SUBMIT_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_fault_submit\0";
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
const DISPATCH_NODE_BOUNDARY_SYMBOL_C: &[u8] =
    b"qemu_plugin_crucible_fault_dispatch_node_boundary\0";
const CAPABILITY_HASH_DOMAIN: &[u8] = b"crucible.qemu-fault-capability.v1\0";
const EXPECTED_QEMU_BUILD_ID: Option<&str> = option_env!("CRUCIBLE_QEMU_BUILD_ID");
const EXPECTED_QEMU_ATOMIC_PATCH_HASH: Option<&str> =
    option_env!("CRUCIBLE_QEMU_ATOMIC_PATCH_HASH");
const EXPECTED_SHMEM_HEADER_HASH: Option<&str> = option_env!("CRUCIBLE_SHMEM_HEADER_HASH");

mod qemu_api;

pub(crate) use qemu_api::QemuFaultCommandApis;
use qemu_api::*;
#[cfg(test)]
use qemu_api::{
    TEST_CAPABILITY_RESULT_PENDING, TEST_DISPATCH_RESULT_PENDING, TEST_DISPATCH_RESULTS,
    test_submit,
};

fn command_kind(value: u16) -> Result<FaultCommandKind, FaultCommandBridgeError> {
    FaultCommandKind::from_u16(value)
        .map_err(|source| FaultCommandBridgeError::CapabilityAbi { source })
}

mod transport;
use transport::*;

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
pub(crate) mod test_support;
use accelerator_evidence::*;
use clock_evidence::*;
use event_envelope::*;
use instruction_evidence::*;
use lifecycle_evidence::*;
#[cfg(test)]
use test_support::{TEST_EVENT_PENDING, test_event_peek, test_event_poll, test_result_for_command};
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
    /// QEMU rejected synchronous node-boundary dispatch.
    #[error("QEMU node-boundary fault dispatch failed with status {status}")]
    NodeBoundaryDispatch {
        /// Negative errno returned by QEMU.
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
