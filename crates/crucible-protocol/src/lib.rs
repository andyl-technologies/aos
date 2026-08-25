//! SPDX-License-Identifier: MIT OR Apache-2.0
//! `crucible-protocol` implements the public host/plugin process protocol.
//! Spec index: RFC-0010 files 14, 16.
//!
//! This dual-licensed L1 crate implements independently implementable framing,
//! versioned codecs, and golden vectors over owned buffers, without QEMU headers,
//! callbacks, native pointers, or private types. Its Unix descriptor handover
//! attaches the shared-memory, wake, and immutable app-random branch-plan
//! descriptors to the setup frame.
//!
//! Module map: the crate root owns the frame-format constants, closed tag
//! registry, message bodies, pure codec, frame I/O helpers, handshake
//! orchestration, setup descriptor passing, and control/data split contract.
//! `app_random_branch_plan` owns the legacy sealed branch-plan body;
//! `app_random_transport` owns the app-random observation transport;
//! `doorbell_abi` owns the shared white-box doorbell instruction ABI;
//! `doorbell_frame` owns the shared white-box doorbell marker frame ABI; `doorbell_marker`
//! owns the marker-kind vocabulary and body codecs; `selectable` owns the
//! guest choice register/request/reply ABI; `selectable_catalog_plan` owns the
//! sealed catalog and continuation launch body; `plugin_setup_plan` owns the
//! composite setup descriptor body; `preemption` owns deterministic IPI
//! arithmetic; `golden_vectors` owns the frozen ABI corpus; `codec_fuzz` owns
//! its fuzz target and corpus.
//!
//! Unsafe boundary discipline: raw `sendmsg`/`recvmsg` and ancillary-buffer
//! details stay private; public callers use safe setup descriptor handover wrappers.
//! These validate the fixed three-fd order and descriptor count before exposing
//! owned close-on-exec descriptors.
//!
//! Wire-format:
//!
//! ```text
//! offset  size  field
//! 0       4     length: u32 big-endian, counting tag + payload bytes
//! 4       1     tag: u8 from the closed ControlTag registry
//! 5       N     payload bytes, tag-specific and big-endian for integers
//! ```

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
pub mod app_random_branch_plan;
pub mod app_random_transport;
mod codec_fuzz;
pub mod debug_gateway;
mod doorbell_abi;
mod doorbell_frame;
mod doorbell_marker;
mod golden_vectors;
pub mod guest_introspection;
pub mod guest_introspection_doorbell;
pub mod plugin_setup_plan;
mod preemption;
mod selectable;
pub mod selectable_catalog_plan;

use std::io::{ErrorKind, Read, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

pub use codec_fuzz::{
    CODEC_FUZZ_REGRESSION_CORPUS, ControlCodecFuzzCase, ControlCodecFuzzOutcome,
    run_control_codec_fuzz_target,
};
pub use doorbell_abi::{
    WHITEBOX_DOORBELL_AARCH64_ABI, WHITEBOX_DOORBELL_AARCH64_HINT_BYTES,
    WHITEBOX_DOORBELL_AARCH64_RESERVED_HINT, WHITEBOX_DOORBELL_ABIS,
    WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION, WHITEBOX_DOORBELL_X86_64_ABI,
    WHITEBOX_DOORBELL_X86_64_OUT_IMM8_AL_BYTES, WHITEBOX_DOORBELL_X86_64_RESERVED_PORT,
    WhiteboxDoorbellAbi, WhiteboxDoorbellArchitecture, WhiteboxDoorbellInstruction,
    WhiteboxDoorbellTrapAbi, encode_aarch64_hint_instruction,
    encode_x86_64_out_imm8_al_instruction, whitebox_doorbell_abi_for_architecture,
};
pub use doorbell_frame::{
    GOLDEN_WHITEBOX_DOORBELL_FRAME_VECTORS, WHITEBOX_DOORBELL_FRAME_HEADER_LEN,
    WHITEBOX_DOORBELL_FRAME_MAGIC, WHITEBOX_DOORBELL_FRAME_REGENERATION_RULE,
    WHITEBOX_DOORBELL_PROTOCOL_VERSION, WhiteboxDoorbellFrame, WhiteboxDoorbellFrameDecodeError,
    WhiteboxDoorbellFrameEncodeError, WhiteboxDoorbellFrameGoldenVector,
    encode_whitebox_doorbell_frame,
};
pub use doorbell_marker::{
    GOLDEN_WHITEBOX_MARKER_PAYLOAD_VECTORS, WHITEBOX_DOORBELL_ASSERTION_FLAVOR_COUNT,
    WHITEBOX_DOORBELL_KIND_ASSERTION, WHITEBOX_DOORBELL_KIND_COVERAGE,
    WHITEBOX_DOORBELL_KIND_EVENT, WHITEBOX_DOORBELL_KIND_LIFECYCLE,
    WHITEBOX_DOORBELL_KIND_MEASUREMENT_BEGIN, WHITEBOX_DOORBELL_KIND_MEASUREMENT_END,
    WHITEBOX_DOORBELL_KIND_METRIC_SAMPLE, WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST,
    WHITEBOX_DOORBELL_KIND_SEMANTIC_MARKER, WHITEBOX_DOORBELL_LIFECYCLE_EVENT_COUNT,
    WHITEBOX_DOORBELL_LIFECYCLE_SETUP_COMPLETE, WHITEBOX_DOORBELL_LIFECYCLE_TEST_DONE,
    WHITEBOX_DOORBELL_MARKER_KIND_COUNT, WHITEBOX_DOORBELL_RANDOM_REQUEST_MAX_WIDTH_BYTES,
    WHITEBOX_MARKER_BODY_MAX_BYTES, WHITEBOX_MEASUREMENT_IDENTIFIER_MAX_BYTES,
    WHITEBOX_MEASUREMENT_VALUE_KIND_COUNT, WHITEBOX_MEASUREMENT_VECTOR_MAX_ELEMENTS,
    WHITEBOX_SEMANTIC_MARKER_MAX_DETAILS, WhiteboxAssertionMarkerBody,
    WhiteboxAssertionMarkerFlavor, WhiteboxCoverageMarkerBody, WhiteboxDoorbellMarkerKind,
    WhiteboxEventMarkerBody, WhiteboxLifecycleMarkerEvent, WhiteboxMarkerDetail,
    WhiteboxMarkerPayload, WhiteboxMarkerPayloadDecodeError, WhiteboxMarkerPayloadEncodeError,
    WhiteboxMarkerPayloadGoldenVector, WhiteboxMeasurementBoundaryBody, WhiteboxMeasurementValue,
    WhiteboxMeasurementValueKind, WhiteboxMetricSampleBody, WhiteboxRandomRequestBody,
    WhiteboxReducedRational, WhiteboxSemanticMarkerBody, WhiteboxSemanticMarkerDetail,
    decode_whitebox_marker_payload, encode_whitebox_marker_frame,
    encode_whitebox_marker_payload_body,
};
pub use golden_vectors::{
    ControlGoldenVector, ControlGoldenVectorMessage, GOLDEN_CONTROL_VECTORS,
    GOLDEN_VECTOR_PROTOCOL_VERSION, GOLDEN_VECTOR_REGENERATION_RULE,
};
pub use preemption::deterministic_ipi_delivery_icount;
pub use selectable::{
    SELECTABLE_DIGEST_BYTES, SELECTABLE_GOLDEN_VECTOR_REGENERATION_RULE,
    SELECTABLE_IDENTIFIER_MAX_BYTES, SELECTABLE_MESSAGE_KIND_REGISTER,
    SELECTABLE_MESSAGE_KIND_REPLY, SELECTABLE_MESSAGE_KIND_REQUEST, SELECTABLE_MESSAGE_MAX_BYTES,
    SELECTABLE_PROTOCOL_VERSION, SELECTABLE_REGISTER_HEADER_BYTES,
    SELECTABLE_SEMANTIC_TAG_MAX_COUNT, SELECTION_REPLY_HEADER_BYTES,
    SELECTION_REQUEST_HEADER_BYTES, SelectableMessageKind, SelectableProtocolError,
    SelectableRegister, SelectionReply, SelectionReplyStatus, SelectionRequest,
    decode_selectable_message_kind, validate_selectable_identifier,
};

use thiserror::Error;

/// Number of bytes in the big-endian frame-length prefix.
pub const FRAME_LENGTH_PREFIX_SIZE: usize = 4;
/// Number of bytes in the frame tag field.
pub const FRAME_TAG_SIZE: usize = 1;
/// Maximum value accepted in the frame-length prefix.
///
/// The length prefix counts the bytes that follow the prefix: one tag byte plus
/// the tag-specific payload bytes.
pub const MAX_FRAME_SIZE: u32 = 64;
/// Maximum payload bytes a single control frame can carry.
pub const MAX_PAYLOAD_SIZE: u32 = MAX_FRAME_SIZE - FRAME_TAG_SIZE as u32;
/// Whether the frame-length prefix counts the tag byte.
pub const FRAME_LENGTH_INCLUDES_TAG: bool = true;
/// Whether all multi-byte integers in frame payloads use big-endian order.
pub const FRAME_INTEGERS_ARE_BIG_ENDIAN: bool = true;
/// Lowest control-protocol version this crate can negotiate.
pub const CONTROL_PROTOCOL_MIN_VERSION: u32 = 2;
/// Highest control-protocol version this crate can negotiate.
pub const CONTROL_PROTOCOL_VERSION: u32 = include!("control_protocol_version.in");
/// Byte length of plugin-to-host per-vCPU register digests.
pub const PLUGIN_NVCPU_REGISTER_DIGEST_BYTES: usize = 32;

/// Validated per-vCPU register material exported by the QEMU plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginVcpuRegisterSnapshot {
    vcpu_id: u32,
    register_digest: [u8; PLUGIN_NVCPU_REGISTER_DIGEST_BYTES],
    register_file_bytes: usize,
    retired_instruction_count: u64,
}

impl PluginVcpuRegisterSnapshot {
    /// Builds one plugin register snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`PluginNvcpuFingerprintSnapshotError::EmptyRegisterFile`] when
    /// `register_file_bytes` is zero.
    pub const fn new(
        vcpu_id: u32,
        register_digest: [u8; PLUGIN_NVCPU_REGISTER_DIGEST_BYTES],
        register_file_bytes: usize,
        retired_instruction_count: u64,
    ) -> Result<Self, PluginNvcpuFingerprintSnapshotError> {
        if register_file_bytes == 0 {
            return Err(PluginNvcpuFingerprintSnapshotError::EmptyRegisterFile { vcpu_id });
        }
        Ok(Self {
            vcpu_id,
            register_digest,
            register_file_bytes,
            retired_instruction_count,
        })
    }

    /// Returns the vCPU identifier.
    #[must_use]
    pub const fn vcpu_id(&self) -> u32 {
        self.vcpu_id
    }

    /// Returns the fixed-width register digest.
    #[must_use]
    pub const fn register_digest(&self) -> &[u8; PLUGIN_NVCPU_REGISTER_DIGEST_BYTES] {
        &self.register_digest
    }

    /// Returns the number of canonical register bytes read by the plugin.
    #[must_use]
    pub const fn register_file_bytes(&self) -> usize {
        self.register_file_bytes
    }

    /// Returns the adapter-provided retired-instruction stamp for the registers.
    #[must_use]
    pub const fn retired_instruction_count(&self) -> u64 {
        self.retired_instruction_count
    }
}

/// Validated round-robin cursor material exported by the QEMU plugin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginRoundRobinCursorSnapshot {
    current_vcpu: u64,
    position_in_quantum: u64,
    rr_switch_quantum: u64,
}

impl PluginRoundRobinCursorSnapshot {
    /// Builds one plugin round-robin cursor snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`PluginNvcpuFingerprintSnapshotError`] when `vcpu_count` is
    /// zero, `current_vcpu` is outside `0..vcpu_count`,
    /// `rr_switch_quantum` is zero, or `position_in_quantum` is outside the
    /// current quantum.
    pub const fn new(
        current_vcpu: u64,
        position_in_quantum: u64,
        rr_switch_quantum: u64,
        vcpu_count: u32,
    ) -> Result<Self, PluginNvcpuFingerprintSnapshotError> {
        if vcpu_count == 0 {
            return Err(PluginNvcpuFingerprintSnapshotError::ZeroVcpuCount);
        }
        if current_vcpu >= vcpu_count as u64 {
            return Err(PluginNvcpuFingerprintSnapshotError::CurrentVcpuOutOfRange {
                current_vcpu,
                vcpu_count,
            });
        }
        if rr_switch_quantum == 0 {
            return Err(PluginNvcpuFingerprintSnapshotError::ZeroSwitchQuantum);
        }
        if position_in_quantum >= rr_switch_quantum {
            return Err(PluginNvcpuFingerprintSnapshotError::CursorPastQuantum {
                position_in_quantum,
                rr_switch_quantum,
            });
        }
        Ok(Self {
            current_vcpu,
            position_in_quantum,
            rr_switch_quantum,
        })
    }

    /// Returns the currently running vCPU.
    #[must_use]
    pub const fn current_vcpu(self) -> u64 {
        self.current_vcpu
    }

    /// Returns the node-icount position inside the current quantum.
    #[must_use]
    pub const fn position_in_quantum(self) -> u64 {
        self.position_in_quantum
    }

    /// Returns the pinned round-robin switch quantum.
    #[must_use]
    pub const fn rr_switch_quantum(self) -> u64 {
        self.rr_switch_quantum
    }
}

/// One plugin-to-host black-box basic-block coverage observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginBasicBlockCoverageObservation {
    current_icount: u64,
    vcpu_index: u32,
    guest_pc: u64,
    block_len: u32,
    map_index: u64,
    was_new: bool,
}

impl PluginBasicBlockCoverageObservation {
    /// Builds one validated plugin basic-block coverage observation.
    ///
    /// # Errors
    ///
    /// Returns [`PluginBasicBlockCoverageObservationError::InvalidBlockLength`]
    /// when QEMU reports a zero-length translated block.
    pub const fn new(
        current_icount: u64,
        vcpu_index: u32,
        guest_pc: u64,
        block_len: u32,
        map_index: u64,
        was_new: bool,
    ) -> Result<Self, PluginBasicBlockCoverageObservationError> {
        if block_len == 0 {
            return Err(PluginBasicBlockCoverageObservationError::InvalidBlockLength { block_len });
        }
        Ok(Self {
            current_icount,
            vcpu_index,
            guest_pc,
            block_len,
            map_index,
            was_new,
        })
    }

    /// Returns the aggregate instruction count at which QEMU reported the block.
    #[must_use]
    pub const fn current_icount(self) -> u64 {
        self.current_icount
    }

    /// Returns the vCPU that executed the translated block.
    #[must_use]
    pub const fn vcpu_index(self) -> u32 {
        self.vcpu_index
    }

    /// Returns the guest program counter for the translated block.
    #[must_use]
    pub const fn guest_pc(self) -> u64 {
        self.guest_pc
    }

    /// Returns the translated block length supplied by QEMU.
    #[must_use]
    pub const fn block_len(self) -> u32 {
        self.block_len
    }

    /// Returns the plugin coverage-map index touched by this block.
    #[must_use]
    pub const fn map_index(self) -> u64 {
        self.map_index
    }

    /// Returns whether this block touched a previously empty coverage-map entry.
    #[must_use]
    pub const fn was_new(self) -> bool {
        self.was_new
    }
}

/// An invalid plugin basic-block coverage observation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PluginBasicBlockCoverageObservationError {
    /// QEMU reported an impossible basic-block length.
    #[error("plugin basic-block coverage length {block_len} is invalid")]
    InvalidBlockLength {
        /// Rejected block length.
        block_len: u32,
    },
}

/// Validated plugin-to-host N-vCPU fingerprint snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginNvcpuFingerprintSnapshot {
    vcpu_registers: Vec<PluginVcpuRegisterSnapshot>,
    rr_cursor: PluginRoundRobinCursorSnapshot,
}

impl PluginNvcpuFingerprintSnapshot {
    /// Builds one validated plugin-to-host fingerprint snapshot.
    ///
    /// Register snapshots are sorted into vCPU-id order and must cover exactly
    /// `0..N`.
    ///
    /// # Errors
    ///
    /// Returns [`PluginNvcpuFingerprintSnapshotError`] when the register set is
    /// empty, non-contiguous, too large for the wire contract, or inconsistent
    /// with the round-robin cursor.
    pub fn new(
        mut vcpu_registers: Vec<PluginVcpuRegisterSnapshot>,
        rr_cursor: PluginRoundRobinCursorSnapshot,
    ) -> Result<Self, PluginNvcpuFingerprintSnapshotError> {
        if vcpu_registers.is_empty() {
            return Err(PluginNvcpuFingerprintSnapshotError::ZeroVcpuCount);
        }
        vcpu_registers.sort_by_key(PluginVcpuRegisterSnapshot::vcpu_id);
        for (expected, register) in vcpu_registers.iter().enumerate() {
            let expected = u32::try_from(expected).map_err(|_error| {
                PluginNvcpuFingerprintSnapshotError::VcpuCountTooLarge {
                    vcpu_count: vcpu_registers.len(),
                }
            })?;
            if register.vcpu_id() != expected {
                return Err(PluginNvcpuFingerprintSnapshotError::MismatchedVcpuSet {
                    expected_vcpu: expected,
                    observed_vcpu: register.vcpu_id(),
                });
            }
        }
        if rr_cursor.current_vcpu() >= vcpu_registers.len() as u64 {
            return Err(PluginNvcpuFingerprintSnapshotError::CurrentVcpuOutOfRange {
                current_vcpu: rr_cursor.current_vcpu(),
                vcpu_count: u32::try_from(vcpu_registers.len()).map_err(|_error| {
                    PluginNvcpuFingerprintSnapshotError::VcpuCountTooLarge {
                        vcpu_count: vcpu_registers.len(),
                    }
                })?,
            });
        }
        Ok(Self {
            vcpu_registers,
            rr_cursor,
        })
    }

    /// Returns sorted per-vCPU register snapshots.
    #[must_use]
    pub fn vcpu_registers(&self) -> &[PluginVcpuRegisterSnapshot] {
        &self.vcpu_registers
    }

    /// Returns the sampled round-robin cursor.
    #[must_use]
    pub const fn rr_cursor(&self) -> PluginRoundRobinCursorSnapshot {
        self.rr_cursor
    }
}

/// Error returned for malformed plugin N-vCPU fingerprint snapshots.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PluginNvcpuFingerprintSnapshotError {
    /// No vCPUs were present in the snapshot.
    #[error("plugin N-vCPU fingerprint snapshot must include at least one vCPU")]
    ZeroVcpuCount,
    /// The snapshot contains more vCPUs than the protocol can index.
    #[error("plugin N-vCPU fingerprint snapshot vCPU count {vcpu_count} is too large")]
    VcpuCountTooLarge {
        /// Number of vCPUs in the snapshot.
        vcpu_count: usize,
    },
    /// One register snapshot had no architectural register bytes.
    #[error("plugin vCPU {vcpu_id} register snapshot is empty")]
    EmptyRegisterFile {
        /// vCPU whose register snapshot was empty.
        vcpu_id: u32,
    },
    /// The current RR cursor vCPU was outside the snapshot's vCPU set.
    #[error("plugin RR current vCPU {current_vcpu} is outside vCPU count {vcpu_count}")]
    CurrentVcpuOutOfRange {
        /// Current vCPU reported by the plugin.
        current_vcpu: u64,
        /// Number of vCPUs in the snapshot.
        vcpu_count: u32,
    },
    /// The pinned RR switch quantum was zero.
    #[error("plugin RR switch quantum must be non-zero")]
    ZeroSwitchQuantum,
    /// The RR cursor position reached or exceeded the pinned quantum.
    #[error(
        "plugin RR cursor position {position_in_quantum} is outside quantum {rr_switch_quantum}"
    )]
    CursorPastQuantum {
        /// Position inside the current quantum.
        position_in_quantum: u64,
        /// Pinned RR switch quantum.
        rr_switch_quantum: u64,
    },
    /// The per-vCPU register set was not exactly `0..N`.
    #[error("plugin register set expected vCPU {expected_vcpu}, observed {observed_vcpu}")]
    MismatchedVcpuSet {
        /// Expected vCPU at this sorted register position.
        expected_vcpu: u32,
        /// Observed vCPU at this sorted register position.
        observed_vcpu: u32,
    },
}

#[cfg(unix)]
const SETUP_DESCRIPTOR_RECV_CAPACITY: usize = SETUP_DESCRIPTOR_COUNT + 1;
#[cfg(unix)]
const ANCILLARY_STORAGE_HEADERS: usize = 8;
#[cfg(all(
    unix,
    any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "watchos"
    )
))]
type MsgControlLen = libc::socklen_t;
#[cfg(all(
    unix,
    not(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "watchos"
    ))
))]
type MsgControlLen = usize;

/// Direction in which a control-frame tag may appear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlDirection {
    /// The host sends this tag to the QEMU plugin.
    HostToPlugin,
    /// The QEMU plugin sends this tag to the host.
    PluginToHost,
}

/// Closed registry of host/plugin control-frame tags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ControlTag {
    /// Host-to-plugin setup frame carrying the shared-memory region length.
    Setup = 0x01,
    /// Plugin-to-host setup acknowledgement frame.
    SetupAck = 0x02,
    /// Host-to-plugin graceful shutdown request.
    Quit = 0x12,
    /// Plugin-to-host handshake offer.
    Hello = 0xF0,
    /// Host-to-plugin handshake acknowledgement.
    HelloAck = 0xF1,
}

/// Setup frame tag value.
pub const TAG_SETUP: u8 = ControlTag::Setup.wire_value();
/// SetupAck frame tag value.
pub const TAG_SETUP_ACK: u8 = ControlTag::SetupAck.wire_value();
/// Quit frame tag value.
pub const TAG_QUIT: u8 = ControlTag::Quit.wire_value();
/// Hello frame tag value.
pub const TAG_HELLO: u8 = ControlTag::Hello.wire_value();
/// HelloAck frame tag value.
pub const TAG_HELLO_ACK: u8 = ControlTag::HelloAck.wire_value();
/// All valid control tags in stable registry order.
pub const ALL_CONTROL_TAGS: [ControlTag; 5] = [
    ControlTag::Setup,
    ControlTag::SetupAck,
    ControlTag::Quit,
    ControlTag::Hello,
    ControlTag::HelloAck,
];

impl ControlTag {
    /// Returns the byte value carried in the frame tag field.
    #[must_use]
    pub const fn wire_value(self) -> u8 {
        self as u8
    }

    /// Returns the only valid direction for this tag.
    #[must_use]
    pub const fn direction(self) -> ControlDirection {
        match self {
            Self::Setup | Self::Quit | Self::HelloAck => ControlDirection::HostToPlugin,
            Self::SetupAck | Self::Hello => ControlDirection::PluginToHost,
        }
    }

    /// Returns the fixed payload length for this tag.
    #[must_use]
    pub const fn payload_len(self) -> usize {
        match self {
            Self::Setup => 8,
            Self::SetupAck => 1,
            Self::Quit => 0,
            Self::Hello => 8,
            Self::HelloAck => 16,
        }
    }

    /// Returns the closed-registry tag for `value`.
    #[must_use]
    pub const fn from_wire_value(value: u8) -> Option<Self> {
        match value {
            TAG_SETUP => Some(Self::Setup),
            TAG_SETUP_ACK => Some(Self::SetupAck),
            TAG_QUIT => Some(Self::Quit),
            TAG_HELLO => Some(Self::Hello),
            TAG_HELLO_ACK => Some(Self::HelloAck),
            _ => None,
        }
    }
}

/// Plugin-to-host control messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PluginMsg {
    /// Handshake offer sent before the plugin touches shared memory.
    Hello {
        /// Highest control-protocol version the plugin can speak.
        proto_version: u32,
        /// Shared-memory ABI version the plugin was built against.
        abi_version: u32,
    },
    /// Setup completion acknowledgement.
    SetupAck {
        /// Zero means ready; any nonzero value means setup failed.
        status: u8,
    },
}

/// Host-to-plugin control messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostMsg {
    /// Handshake acknowledgement carrying the negotiated versions and slot.
    HelloAck {
        /// Negotiated control-protocol version.
        proto_version: u32,
        /// Host shared-memory ABI version.
        abi_version: u32,
        /// Zero-based shared-memory node slot assigned to this plugin.
        slot_index: u32,
        /// Number of node slots in the shared-memory region.
        node_count: u32,
    },
    /// Setup frame carrying the region byte length.
    Setup {
        /// Total byte length of the shared-memory region to map.
        region_len: u64,
    },
    /// Graceful shutdown request.
    Quit,
}

/// Number of file descriptors attached to a `Setup` frame.
#[cfg(unix)]
pub const SETUP_DESCRIPTOR_COUNT: usize = 3;
/// `SetupAck.status` value meaning the plugin is ready to run via shared memory.
pub const SETUP_ACK_STATUS_READY: u8 = 0;
/// Generic `SetupAck.status` value for setup failures without a narrower code.
pub const SETUP_ACK_STATUS_SETUP_FAILED: u8 = 1;

/// Borrowed descriptors attached to an outbound `Setup` frame.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupDescriptorFds {
    /// Shared-memory region descriptor, sent first in the `SCM_RIGHTS` list.
    pub shmem_fd: RawFd,
    /// Wake descriptor, sent second in the `SCM_RIGHTS` list.
    pub wake_fd: RawFd,
    /// Sealed app-random branch-plan descriptor, sent third.
    pub app_random_branch_plan_fd: RawFd,
}

/// Owned descriptors received from an inbound `Setup` frame.
#[cfg(unix)]
#[derive(Debug)]
pub struct ReceivedSetupDescriptors {
    /// Shared-memory region descriptor received first in the `SCM_RIGHTS` list.
    pub shmem_fd: OwnedFd,
    /// Wake descriptor received second in the `SCM_RIGHTS` list.
    pub wake_fd: OwnedFd,
    /// Sealed app-random branch-plan descriptor received third.
    pub app_random_branch_plan_fd: OwnedFd,
}

/// A decoded `Setup` frame plus its attached descriptors.
#[cfg(unix)]
#[derive(Debug)]
pub struct ReceivedSetup {
    /// Total byte length of the shared-memory region to map.
    pub region_len: u64,
    /// Fixed-order descriptors attached to the setup frame.
    pub descriptors: ReceivedSetupDescriptors,
}

/// Host-side proof that a node's setup completed before scheduling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedulableNodeSetup {
    status: u8,
}

impl SchedulableNodeSetup {
    /// Returns the accepted `SetupAck.status` byte.
    #[must_use]
    pub const fn setup_ack_status(self) -> u8 {
        self.status
    }

    /// Returns whether this setup acknowledgement permits scheduling.
    #[must_use]
    pub const fn can_schedule(self) -> bool {
        true
    }
}

/// Host-side inputs used to accept the initial `Hello` handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostHandshakeConfig {
    /// Highest control-protocol version supported by the host.
    pub proto_version: u32,
    /// Shared-memory ABI version used to build the region.
    pub abi_version: u32,
    /// Zero-based shared-memory slot assigned to this plugin.
    pub slot_index: u32,
    /// Total number of slots in the shared-memory region.
    pub node_count: u32,
}

/// Plugin-side inputs used to start the initial `Hello` handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginHandshakeConfig {
    /// Highest control-protocol version supported by the plugin.
    pub proto_version: u32,
    /// Shared-memory ABI version compiled into the plugin.
    pub abi_version: u32,
}

/// A successful `Hello`/`HelloAck` negotiation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NegotiatedHandshake {
    /// Single negotiated control-protocol version both peers must speak.
    pub proto_version: u32,
    /// Shared-memory ABI version both peers agreed on exactly.
    pub abi_version: u32,
    /// Zero-based shared-memory slot assigned to this plugin.
    pub slot_index: u32,
    /// Total number of slots in the shared-memory region.
    pub node_count: u32,
}

/// Typed errors returned by pure control-frame decoding.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FrameDecodeError {
    /// The byte buffer is empty.
    #[error("control frame is empty")]
    EmptyFrame,
    /// The buffer does not contain the full four-byte length prefix.
    #[error("control frame length prefix is truncated: actual {actual} bytes")]
    TruncatedLengthPrefix {
        /// Number of bytes available for the length prefix.
        actual: usize,
    },
    /// The decoded length exceeds [`MAX_FRAME_SIZE`].
    #[error("control frame length {length} exceeds maximum {max}")]
    LengthExceedsMax {
        /// Decoded frame length, counting tag plus payload bytes.
        length: u32,
        /// Maximum permitted frame length, counting tag plus payload bytes.
        max: u32,
    },
    /// The frame declares more bytes than the supplied buffer contains.
    #[error("control frame payload is truncated: declared {declared} bytes, actual {actual} bytes")]
    TruncatedPayload {
        /// Declared length, counting tag plus payload bytes.
        declared: usize,
        /// Actual bytes after the length prefix.
        actual: usize,
    },
    /// The supplied buffer contains bytes beyond the declared frame.
    #[error("control frame has trailing bytes: declared {declared} bytes, actual {actual} bytes")]
    TrailingBytes {
        /// Declared length, counting tag plus payload bytes.
        declared: usize,
        /// Actual bytes after the length prefix.
        actual: usize,
    },
    /// The frame has a zero length and therefore no tag byte.
    #[error("control frame is missing its tag byte")]
    MissingTag,
    /// The tag byte is not in the closed registry.
    #[error("unknown control frame tag 0x{tag:02x}")]
    UnknownTag {
        /// Unregistered tag byte.
        tag: u8,
    },
    /// The tag is valid but belongs to the other protocol direction.
    #[error("control frame tag {tag:?} has direction {actual:?}, expected {expected:?}")]
    UnexpectedDirection {
        /// Decoded tag.
        tag: ControlTag,
        /// Direction required by the selected decoder.
        expected: ControlDirection,
        /// Direction registered for the decoded tag.
        actual: ControlDirection,
    },
    /// The tag-specific payload is shorter than the registered shape.
    #[error(
        "control frame tag {tag:?} payload is too short: expected {expected} bytes, actual {actual} bytes"
    )]
    PayloadTooShort {
        /// Decoded tag.
        tag: ControlTag,
        /// Required payload byte length.
        expected: usize,
        /// Actual payload byte length.
        actual: usize,
    },
    /// The tag-specific payload is longer than the registered shape.
    #[error(
        "control frame tag {tag:?} payload is too long: expected {expected} bytes, actual {actual} bytes"
    )]
    PayloadTooLong {
        /// Decoded tag.
        tag: ControlTag,
        /// Required payload byte length.
        expected: usize,
        /// Actual payload byte length.
        actual: usize,
    },
}

/// Typed errors returned by frame stream read/write helpers.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum FrameIoError {
    /// The stream ended before a complete four-byte length prefix arrived.
    #[error("control frame stream ended during length prefix")]
    TruncatedLengthPrefix,
    /// The decoded length exceeds [`MAX_FRAME_SIZE`].
    #[error("control frame length {length} exceeds maximum {max}")]
    LengthExceedsMax {
        /// Decoded frame length, counting tag plus payload bytes.
        length: u32,
        /// Maximum permitted frame length, counting tag plus payload bytes.
        max: u32,
    },
    /// The stream ended before the declared frame payload arrived.
    #[error("control frame stream ended during payload of {length} bytes")]
    TruncatedPayload {
        /// Declared length, counting tag plus payload bytes.
        length: u32,
    },
    /// The underlying stream returned a non-EOF I/O error.
    #[error("{operation} failed with {kind:?}")]
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Error kind returned by the stream.
        kind: ErrorKind,
    },
}

/// Typed errors returned by the initial protocol handshake.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum HandshakeError {
    /// A control-frame read or write failed.
    #[error("handshake I/O failed")]
    Io {
        /// Underlying frame I/O error.
        source: FrameIoError,
    },
    /// A handshake frame failed byte-level decoding.
    #[error("handshake frame decode failed")]
    Decode {
        /// Underlying frame decode error.
        source: FrameDecodeError,
    },
    /// The decoded frame had the wrong direction or message kind.
    #[error("unexpected handshake message: {message:?}")]
    UnexpectedPluginMessage {
        /// Decoded plugin-to-host message.
        message: PluginMsg,
    },
    /// The decoded frame had the wrong direction or message kind.
    #[error("unexpected handshake message: {message:?}")]
    UnexpectedHostMessage {
        /// Decoded host-to-plugin message.
        message: HostMsg,
    },
    /// Host and plugin protocol-version ranges do not overlap.
    #[error(
        "no control-protocol version overlap: plugin max {plugin_max}, host range {host_min}..={host_max}"
    )]
    ProtocolVersionNoOverlap {
        /// Highest control-protocol version offered by the plugin.
        plugin_max: u32,
        /// Lowest control-protocol version supported by the host.
        host_min: u32,
        /// Highest control-protocol version supported by the host.
        host_max: u32,
    },
    /// The host replied with a protocol version the plugin cannot speak.
    #[error(
        "negotiated control-protocol version {negotiated} is outside plugin range {plugin_min}..={plugin_max}"
    )]
    NegotiatedProtocolOutOfRange {
        /// Protocol version sent in `HelloAck`.
        negotiated: u32,
        /// Lowest control-protocol version supported by the plugin.
        plugin_min: u32,
        /// Highest control-protocol version offered by the plugin.
        plugin_max: u32,
    },
    /// Host and plugin shmem ABI versions differ.
    #[error("shared-memory ABI mismatch: plugin {plugin_abi}, host {host_abi}")]
    AbiMismatch {
        /// ABI version offered by the plugin.
        plugin_abi: u32,
        /// ABI version required by the host.
        host_abi: u32,
    },
    /// The host assigned a slot outside the declared node range.
    #[error("assigned slot {slot_index} is outside node_count {node_count}")]
    InvalidSlot {
        /// Slot index carried in `HelloAck`.
        slot_index: u32,
        /// Node count carried in `HelloAck`.
        node_count: u32,
    },
}

/// Typed errors returned by setup-completion acknowledgement handling.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SetupCompletionError {
    /// A control-frame read or write failed.
    #[error("setup completion I/O failed")]
    Io {
        /// Underlying frame I/O error.
        source: FrameIoError,
    },
    /// A setup-completion frame failed byte-level decoding.
    #[error("setup completion frame decode failed")]
    Decode {
        /// Underlying frame decode error.
        source: FrameDecodeError,
    },
    /// The decoded frame was not a plugin `SetupAck` message.
    #[error("unexpected setup completion message: {message:?}")]
    UnexpectedPluginMessage {
        /// Decoded plugin-to-host message.
        message: PluginMsg,
    },
    /// The plugin reported a setup failure and must not be scheduled.
    #[error("setup acknowledgement status {status} is non-zero")]
    NonZeroSetupAck {
        /// Nonzero `SetupAck.status` byte.
        status: u8,
    },
}

/// Protocol lifecycle state for one host/plugin control socket.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ControlLifecycleState {
    /// No per-node control socket has been connected yet.
    #[default]
    Disconnected,
    /// A connected Unix stream socket pair exists for this node.
    Connected,
    /// The plugin has sent `Hello`.
    HelloSent,
    /// The host has replied with `HelloAck`.
    HelloAcknowledged,
    /// The host has sent `Setup` with the shmem and wake descriptors.
    SetupSent,
    /// The plugin has replied with `SetupAck(status = 0)`.
    SetupAcknowledged,
    /// Runtime synchronization is flowing through shared memory, not control frames.
    RunningViaSharedMemory,
    /// The host has sent `Quit` to end the run.
    QuitSent,
}

/// A lifecycle event observed on one host/plugin control socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlLifecycleEvent {
    /// The host created and connected an `AF_UNIX`/`SOCK_STREAM` socket pair.
    ConnectUnixStreamSocketPair,
    /// The plugin sent a `Hello` frame.
    PluginHello,
    /// The host sent a `HelloAck` frame.
    HostHelloAck,
    /// The host sent a `Setup` frame with the setup descriptors.
    HostSetup,
    /// The plugin sent a `SetupAck` frame.
    PluginSetupAck {
        /// The `SetupAck.status` byte.
        status: u8,
    },
    /// The node performed runtime synchronization through shared memory.
    RunViaSharedMemory,
    /// The host sent a `Quit` frame.
    HostQuit,
}

impl ControlLifecycleEvent {
    /// Returns the lifecycle event represented by a decoded plugin message.
    #[must_use]
    pub const fn from_plugin_msg(message: &PluginMsg) -> Self {
        match message {
            PluginMsg::Hello { .. } => Self::PluginHello,
            PluginMsg::SetupAck { status } => Self::PluginSetupAck { status: *status },
        }
    }

    /// Returns the lifecycle event represented by a decoded host message.
    #[must_use]
    pub const fn from_host_msg(message: &HostMsg) -> Self {
        match message {
            HostMsg::HelloAck { .. } => Self::HostHelloAck,
            HostMsg::Setup { .. } => Self::HostSetup,
            HostMsg::Quit => Self::HostQuit,
        }
    }

    /// Returns the control tag carried by this event, when it is a control frame.
    #[must_use]
    pub const fn control_tag(self) -> Option<ControlTag> {
        match self {
            Self::ConnectUnixStreamSocketPair | Self::RunViaSharedMemory => None,
            Self::PluginHello => Some(ControlTag::Hello),
            Self::HostHelloAck => Some(ControlTag::HelloAck),
            Self::HostSetup => Some(ControlTag::Setup),
            Self::PluginSetupAck { .. } => Some(ControlTag::SetupAck),
            Self::HostQuit => Some(ControlTag::Quit),
        }
    }
}

/// Canonical normal lifecycle for one host/plugin control socket.
pub const NORMAL_CONTROL_LIFECYCLE: [ControlLifecycleEvent; 7] = [
    ControlLifecycleEvent::ConnectUnixStreamSocketPair,
    ControlLifecycleEvent::PluginHello,
    ControlLifecycleEvent::HostHelloAck,
    ControlLifecycleEvent::HostSetup,
    ControlLifecycleEvent::PluginSetupAck {
        status: SETUP_ACK_STATUS_READY,
    },
    ControlLifecycleEvent::RunViaSharedMemory,
    ControlLifecycleEvent::HostQuit,
];

/// Typed errors returned by control lifecycle validation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ControlLifecycleError {
    /// A lifecycle event was observed before its prerequisites completed.
    #[error("control lifecycle event {event:?} is invalid in state {state:?}")]
    UnexpectedEvent {
        /// Lifecycle state when the event was observed.
        state: ControlLifecycleState,
        /// Event that violated lifecycle order.
        event: ControlLifecycleEvent,
    },
    /// A non-ready `SetupAck` tried to enter the run lifecycle.
    #[error("setup acknowledgement status {status} does not enter the run lifecycle")]
    NonReadySetupAck {
        /// Nonzero `SetupAck.status` byte.
        status: u8,
    },
    /// A control frame was observed after the run entered the shared-memory hot path.
    #[error("control frame {tag:?} with direction {direction:?} was observed during run")]
    ControlFrameDuringRun {
        /// Tag observed during the run.
        tag: ControlTag,
        /// Direction registered for the tag.
        direction: ControlDirection,
    },
    /// The trace ended before the normal lifecycle reached `Quit`.
    #[error("control lifecycle ended incomplete in state {state:?}")]
    IncompleteLifecycle {
        /// Final state reached by the trace.
        state: ControlLifecycleState,
    },
}

/// Typed errors returned by lifecycle-aware control stream operations.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ControlLifecycleIoError {
    /// The operation violated the control lifecycle.
    #[error("control lifecycle violation")]
    Lifecycle {
        /// Underlying lifecycle error.
        source: ControlLifecycleError,
    },
    /// A control-frame read or write failed.
    #[error("control lifecycle I/O failed")]
    Io {
        /// Underlying frame I/O error.
        source: FrameIoError,
    },
    /// A control frame failed byte-level decoding.
    #[error("control lifecycle frame decode failed")]
    Decode {
        /// Underlying frame decode error.
        source: FrameDecodeError,
    },
    /// A handshake operation failed.
    #[error("control lifecycle handshake failed")]
    Handshake {
        /// Underlying handshake error.
        source: HandshakeError,
    },
    /// A setup-completion operation failed.
    #[error("control lifecycle setup completion failed")]
    SetupCompletion {
        /// Underlying setup-completion error.
        source: SetupCompletionError,
    },
    /// A setup descriptor handover operation failed.
    #[cfg(unix)]
    #[error("control lifecycle setup descriptor handover failed")]
    DescriptorHandover {
        /// Underlying descriptor handover error.
        source: DescriptorHandoverError,
    },
}

impl From<ControlLifecycleError> for ControlLifecycleIoError {
    fn from(source: ControlLifecycleError) -> Self {
        Self::Lifecycle { source }
    }
}

impl From<FrameIoError> for ControlLifecycleIoError {
    fn from(source: FrameIoError) -> Self {
        Self::Io { source }
    }
}

impl From<FrameDecodeError> for ControlLifecycleIoError {
    fn from(source: FrameDecodeError) -> Self {
        Self::Decode { source }
    }
}

impl From<HandshakeError> for ControlLifecycleIoError {
    fn from(source: HandshakeError) -> Self {
        Self::Handshake { source }
    }
}

impl From<SetupCompletionError> for ControlLifecycleIoError {
    fn from(source: SetupCompletionError) -> Self {
        Self::SetupCompletion { source }
    }
}

#[cfg(unix)]
impl From<DescriptorHandoverError> for ControlLifecycleIoError {
    fn from(source: DescriptorHandoverError) -> Self {
        Self::DescriptorHandover { source }
    }
}

/// A validator for the ordered control lifecycle of one node.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ControlLifecycle {
    state: ControlLifecycleState,
}

impl ControlLifecycle {
    /// Returns a new lifecycle validator in the disconnected state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: ControlLifecycleState::Disconnected,
        }
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ControlLifecycleState {
        self.state
    }

    /// Applies one observed lifecycle event.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleError`] when the event is out of order, when a
    /// nonzero `SetupAck` tries to enter the run lifecycle, or when any control
    /// frame other than `Quit` is observed after the run has moved to shared
    /// memory.
    pub fn observe(
        &mut self,
        event: ControlLifecycleEvent,
    ) -> Result<ControlLifecycleState, ControlLifecycleError> {
        let state = next_lifecycle_state(self.state, event)?;
        self.state = state;
        Ok(state)
    }
}

/// A control stream coupled to the normal host/plugin lifecycle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlLifecycleStream<S> {
    stream: S,
    lifecycle: ControlLifecycle,
}

impl<S> ControlLifecycleStream<S> {
    /// Wraps a connected Unix stream socket pair endpoint.
    ///
    /// The caller owns construction of the `AF_UNIX`/`SOCK_STREAM` socket pair;
    /// this method records the lifecycle connect event before any frame I/O is
    /// permitted.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] if the connect event is invalid for a
    /// newly-created lifecycle.
    pub fn connected_unix_stream(stream: S) -> Result<Self, ControlLifecycleIoError> {
        let mut lifecycle = ControlLifecycle::new();
        lifecycle.observe(ControlLifecycleEvent::ConnectUnixStreamSocketPair)?;
        Ok(Self { stream, lifecycle })
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ControlLifecycleState {
        self.lifecycle.state()
    }

    /// Returns the wrapped stream.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Borrows the setup-phase stream for plugin setup failure reporting.
    ///
    /// Descriptor mapping, wake-fd arming, and callback registration can fail
    /// after the lifecycle has accepted `Setup` but before the ready
    /// acknowledgement is committed. Those paths must send a nonzero
    /// `SetupAck` through the same socket without pretending that the node
    /// entered the run lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] unless the lifecycle is waiting for
    /// `Setup` or has consumed it and is waiting for the plugin acknowledgement.
    pub fn plugin_setup_io_mut(&mut self) -> Result<&mut S, ControlLifecycleIoError> {
        match self.lifecycle.state() {
            ControlLifecycleState::HelloAcknowledged | ControlLifecycleState::SetupSent => {
                Ok(&mut self.stream)
            }
            state => Err(ControlLifecycleError::UnexpectedEvent {
                state,
                event: ControlLifecycleEvent::HostSetup,
            }
            .into()),
        }
    }

    /// Records a ready `SetupAck` already written by plugin setup code.
    ///
    /// This is the lifecycle counterpart to [`Self::plugin_setup_io_mut`] for
    /// setup code that must validate callback and wake-fd ownership before it
    /// can choose between a ready or failure acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] unless the lifecycle is waiting for
    /// setup acknowledgement.
    pub fn plugin_commit_ready_setup_ack(&mut self) -> Result<(), ControlLifecycleIoError> {
        self.lifecycle
            .observe(ControlLifecycleEvent::PluginSetupAck {
                status: SETUP_ACK_STATUS_READY,
            })
            .map(|_state| ())
            .map_err(ControlLifecycleIoError::from)
    }
}

#[cfg(unix)]
impl<S> AsRawFd for ControlLifecycleStream<S>
where
    S: AsRawFd,
{
    fn as_raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }
}

impl<S> ControlLifecycleStream<S>
where
    S: Read + Write,
{
    /// Runs the host side of `Hello`/`HelloAck` through the lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] when the frame I/O fails, when the
    /// decoded message is invalid for the handshake, or when the observed
    /// lifecycle event is out of order.
    pub fn host_accept_handshake(
        &mut self,
        config: HostHandshakeConfig,
    ) -> Result<NegotiatedHandshake, ControlLifecycleIoError> {
        let frame = read_control_frame(&mut self.stream)?;
        let message = control_decode_plugin_msg(&frame)?;
        self.lifecycle
            .observe(ControlLifecycleEvent::from_plugin_msg(&message))?;

        let negotiated = host_negotiate_handshake(message, config)?;
        let ack = HostMsg::HelloAck {
            proto_version: negotiated.proto_version,
            abi_version: negotiated.abi_version,
            slot_index: negotiated.slot_index,
            node_count: negotiated.node_count,
        };
        let ack = control_encode_host_msg(&ack);
        write_control_frame(&mut self.stream, &ack)?;
        self.lifecycle
            .observe(ControlLifecycleEvent::HostHelloAck)?;
        Ok(negotiated)
    }

    /// Runs the plugin side of `Hello`/`HelloAck` through the lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] when the frame I/O fails, when the
    /// decoded host acknowledgement is invalid, or when the observed lifecycle
    /// event is out of order.
    pub fn plugin_start_handshake(
        &mut self,
        config: PluginHandshakeConfig,
    ) -> Result<NegotiatedHandshake, ControlLifecycleIoError> {
        let mut lifecycle = self.lifecycle.clone();
        lifecycle.observe(ControlLifecycleEvent::PluginHello)?;
        let hello = PluginMsg::Hello {
            proto_version: config.proto_version,
            abi_version: config.abi_version,
        };
        let hello = control_encode_plugin_msg(&hello);
        write_control_frame(&mut self.stream, &hello)?;
        self.lifecycle = lifecycle;

        let frame = read_control_frame(&mut self.stream)?;
        let message = control_decode_host_msg(&frame)?;
        let negotiated = plugin_validate_handshake_ack(message.clone(), config)?;
        self.lifecycle
            .observe(ControlLifecycleEvent::from_host_msg(&message))?;
        Ok(negotiated)
    }
}

impl<S> ControlLifecycleStream<S>
where
    S: Read,
{
    /// Reads and validates the host-side `SetupAck` through the lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] when the frame cannot be read or
    /// decoded, when the decoded message is not a ready `SetupAck`, or when the
    /// lifecycle is not waiting for setup completion.
    pub fn host_accept_setup_ack(
        &mut self,
    ) -> Result<SchedulableNodeSetup, ControlLifecycleIoError> {
        ensure_waiting_for_setup_ack(self.lifecycle.state())?;
        let frame = read_control_frame(&mut self.stream)?;
        let message = control_decode_plugin_msg(&frame)?;
        let setup = host_validate_setup_ack(message.clone())?;
        self.lifecycle
            .observe(ControlLifecycleEvent::from_plugin_msg(&message))?;
        Ok(setup)
    }

    /// Reads one host-side control frame while the node is running via shared memory.
    ///
    /// The host is the side that initiates `Quit`, so any inbound frame observed
    /// by the host during the run is a run-phase protocol fault.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] when reading or decoding fails, when
    /// the lifecycle is not in the run phase, or when any control frame is
    /// observed.
    pub fn host_read_run_control_frame(
        &mut self,
    ) -> Result<ControlLifecycleState, ControlLifecycleIoError> {
        ensure_running_via_shared_memory(self.lifecycle.state())?;
        let frame = read_control_frame(&mut self.stream)?;
        let tag = control_frame_tag(&frame)?;
        Err(ControlLifecycleError::ControlFrameDuringRun {
            tag,
            direction: tag.direction(),
        }
        .into())
    }

    /// Reads one plugin-side control frame while the node is running via shared memory.
    ///
    /// `Quit` from the host transitions out of the run. Any other valid control
    /// frame is a run-phase protocol fault because runtime traffic must stay in
    /// shared memory.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] when reading or decoding fails, when
    /// the lifecycle is not in the run phase, or when the next frame is any
    /// control frame other than host `Quit`.
    pub fn plugin_read_run_control_frame(
        &mut self,
    ) -> Result<ControlLifecycleState, ControlLifecycleIoError> {
        ensure_running_via_shared_memory(self.lifecycle.state())?;
        let frame = read_control_frame(&mut self.stream)?;
        let tag = control_frame_tag(&frame)?;
        if tag != ControlTag::Quit {
            return Err(ControlLifecycleError::ControlFrameDuringRun {
                tag,
                direction: tag.direction(),
            }
            .into());
        }

        let message = control_decode_host_msg(&frame)?;
        self.lifecycle
            .observe(ControlLifecycleEvent::from_host_msg(&message))
            .map_err(ControlLifecycleIoError::from)
    }
}

impl<S> ControlLifecycleStream<S>
where
    S: Write,
{
    /// Sends a terminal non-ready `SetupAck` without entering the run lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] when setup has not begun or the
    /// failure acknowledgement cannot be written.
    pub fn plugin_send_setup_failure_ack(&mut self) -> Result<(), ControlLifecycleIoError> {
        match self.lifecycle.state() {
            ControlLifecycleState::HelloAcknowledged | ControlLifecycleState::SetupSent => {}
            state => {
                return Err(ControlLifecycleError::UnexpectedEvent {
                    state,
                    event: ControlLifecycleEvent::PluginSetupAck {
                        status: SETUP_ACK_STATUS_SETUP_FAILED,
                    },
                }
                .into());
            }
        }
        plugin_send_setup_ack(&mut self.stream, SETUP_ACK_STATUS_SETUP_FAILED)?;
        Ok(())
    }

    /// Sends a ready `SetupAck` through the lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] when the stream write fails or when
    /// the lifecycle is not waiting for setup completion.
    pub fn plugin_send_ready_setup_ack(&mut self) -> Result<(), ControlLifecycleIoError> {
        let mut lifecycle = self.lifecycle.clone();
        lifecycle.observe(ControlLifecycleEvent::PluginSetupAck {
            status: SETUP_ACK_STATUS_READY,
        })?;
        plugin_send_setup_ack(&mut self.stream, SETUP_ACK_STATUS_READY)?;
        self.lifecycle = lifecycle;
        Ok(())
    }

    /// Sends `Quit` through the lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] when `Quit` is attempted before the
    /// shared-memory run starts, or when writing the frame fails.
    pub fn host_send_quit(&mut self) -> Result<(), ControlLifecycleIoError> {
        let mut lifecycle = self.lifecycle.clone();
        lifecycle.observe(ControlLifecycleEvent::HostQuit)?;
        let quit = control_encode_host_msg(&HostMsg::Quit);
        write_control_frame(&mut self.stream, &quit)?;
        self.lifecycle = lifecycle;
        Ok(())
    }
}

impl<S> ControlLifecycleStream<S> {
    /// Enters the shared-memory run phase after ready setup acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] when setup has not completed
    /// successfully.
    pub fn enter_run_via_shared_memory(&mut self) -> Result<(), ControlLifecycleIoError> {
        self.lifecycle
            .observe(ControlLifecycleEvent::RunViaSharedMemory)
            .map(|_| ())
            .map_err(ControlLifecycleIoError::from)
    }
}

#[cfg(unix)]
impl<S> ControlLifecycleStream<S>
where
    S: AsRawFd,
{
    /// Sends `Setup` and its fixed-order descriptors through the lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] when the lifecycle is not waiting for
    /// setup, or when `sendmsg` fails to transfer the frame and descriptors.
    pub fn host_send_setup_with_descriptors(
        &mut self,
        region_len: u64,
        descriptors: SetupDescriptorFds,
    ) -> Result<(), ControlLifecycleIoError> {
        let mut lifecycle = self.lifecycle.clone();
        lifecycle.observe(ControlLifecycleEvent::HostSetup)?;
        send_setup_with_descriptors(self.stream.as_raw_fd(), region_len, descriptors)?;
        self.lifecycle = lifecycle;
        Ok(())
    }

    /// Receives `Setup` and its fixed-order descriptors through the lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLifecycleIoError`] when the lifecycle is not waiting for
    /// setup, or when descriptor handover fails.
    pub fn plugin_recv_setup_with_descriptors(
        &mut self,
    ) -> Result<ReceivedSetup, ControlLifecycleIoError> {
        let mut lifecycle = self.lifecycle.clone();
        lifecycle.observe(ControlLifecycleEvent::HostSetup)?;
        let setup = recv_setup_with_descriptors(self.stream.as_raw_fd())?;
        self.lifecycle = lifecycle;
        Ok(setup)
    }
}

/// Validates an ordered control lifecycle trace and returns the final state.
///
/// # Errors
///
/// Returns [`ControlLifecycleError`] when any event violates the normal control
/// lifecycle or when a control frame is observed during the shared-memory run.
pub fn validate_control_lifecycle_trace(
    events: impl IntoIterator<Item = ControlLifecycleEvent>,
) -> Result<ControlLifecycleState, ControlLifecycleError> {
    let mut lifecycle = ControlLifecycle::new();
    for event in events {
        lifecycle.observe(event)?;
    }
    Ok(lifecycle.state())
}

/// Validates that an ordered control lifecycle trace reaches `Quit`.
///
/// # Errors
///
/// Returns [`ControlLifecycleError`] when any event violates lifecycle order,
/// when a control frame is observed during the shared-memory run, or when the
/// trace ends before `Quit`.
pub fn validate_complete_control_lifecycle(
    events: impl IntoIterator<Item = ControlLifecycleEvent>,
) -> Result<(), ControlLifecycleError> {
    let state = validate_control_lifecycle_trace(events)?;
    if state == ControlLifecycleState::QuitSent {
        Ok(())
    } else {
        Err(ControlLifecycleError::IncompleteLifecycle { state })
    }
}

/// Typed errors returned by Unix setup descriptor handover.
#[cfg(unix)]
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DescriptorHandoverError {
    /// A syscall returned an OS error.
    #[error("{operation} failed with errno {errno}")]
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Raw `errno` value reported by the OS.
        errno: i32,
    },
    /// The peer closed the socket before a complete setup frame arrived.
    #[error("{operation} ended before setup completed")]
    PeerClosed {
        /// Operation being attempted.
        operation: &'static str,
    },
    /// `sendmsg` accepted fewer bytes than the complete setup frame.
    #[error("setup sendmsg wrote {actual} bytes, expected {expected}")]
    ShortWrite {
        /// Complete setup frame byte length.
        expected: usize,
        /// Bytes reported by `sendmsg`.
        actual: usize,
    },
    /// The received setup frame failed byte-level decoding.
    #[error("setup frame decode failed")]
    Decode {
        /// Underlying frame decode error.
        source: FrameDecodeError,
    },
    /// The frame decoded successfully but was not a `Setup` message.
    #[error("expected Setup frame, received {message:?}")]
    UnexpectedMessage {
        /// Decoded host-to-plugin message.
        message: HostMsg,
    },
    /// The setup frame carried the wrong descriptor count.
    #[error("setup frame carried {count} descriptors, expected 2")]
    WrongDescriptorCount {
        /// Number of descriptors received with the setup frame.
        count: usize,
    },
    /// The ancillary data was truncated by the kernel.
    #[error("setup SCM_RIGHTS ancillary data was truncated")]
    AncillaryTruncated,
    /// The ancillary data could not be parsed as whole file descriptors.
    #[error("setup SCM_RIGHTS ancillary data is malformed: {reason}")]
    MalformedAncillary {
        /// Short reason for the parse failure.
        reason: &'static str,
    },
}

/// Encodes a plugin-to-host control message as a complete frame.
#[must_use]
pub fn control_encode_plugin_msg(message: &PluginMsg) -> Vec<u8> {
    match message {
        PluginMsg::Hello {
            proto_version,
            abi_version,
        } => encode_frame(
            ControlTag::Hello,
            &[
                FieldValue::U32(*proto_version),
                FieldValue::U32(*abi_version),
            ],
        ),
        PluginMsg::SetupAck { status } => {
            encode_frame(ControlTag::SetupAck, &[FieldValue::U8(*status)])
        }
    }
}

/// Decodes a complete plugin-to-host control frame.
///
/// # Errors
///
/// Returns [`FrameDecodeError`] when the frame bytes are empty, truncated,
/// oversized, tagged with an unknown or wrong-direction tag, or carry a payload
/// length that does not match the tag registry.
pub fn control_decode_plugin_msg(frame: &[u8]) -> Result<PluginMsg, FrameDecodeError> {
    let decoded = decode_frame(frame, ControlDirection::PluginToHost)?;
    match decoded.tag {
        ControlTag::Hello => Ok(PluginMsg::Hello {
            proto_version: read_u32_be(decoded.payload, 0),
            abi_version: read_u32_be(decoded.payload, 4),
        }),
        ControlTag::SetupAck => Ok(PluginMsg::SetupAck {
            status: decoded.payload[0],
        }),
        ControlTag::Setup | ControlTag::Quit | ControlTag::HelloAck => {
            Err(FrameDecodeError::UnexpectedDirection {
                tag: decoded.tag,
                expected: ControlDirection::PluginToHost,
                actual: decoded.tag.direction(),
            })
        }
    }
}

/// Encodes a host-to-plugin control message as a complete frame.
#[must_use]
pub fn control_encode_host_msg(message: &HostMsg) -> Vec<u8> {
    match message {
        HostMsg::HelloAck {
            proto_version,
            abi_version,
            slot_index,
            node_count,
        } => encode_frame(
            ControlTag::HelloAck,
            &[
                FieldValue::U32(*proto_version),
                FieldValue::U32(*abi_version),
                FieldValue::U32(*slot_index),
                FieldValue::U32(*node_count),
            ],
        ),
        HostMsg::Setup { region_len } => {
            encode_frame(ControlTag::Setup, &[FieldValue::U64(*region_len)])
        }
        HostMsg::Quit => encode_frame(ControlTag::Quit, &[]),
    }
}

/// Decodes a complete host-to-plugin control frame.
///
/// # Errors
///
/// Returns [`FrameDecodeError`] when the frame bytes are empty, truncated,
/// oversized, tagged with an unknown or wrong-direction tag, or carry a payload
/// length that does not match the tag registry.
pub fn control_decode_host_msg(frame: &[u8]) -> Result<HostMsg, FrameDecodeError> {
    let decoded = decode_frame(frame, ControlDirection::HostToPlugin)?;
    match decoded.tag {
        ControlTag::HelloAck => Ok(HostMsg::HelloAck {
            proto_version: read_u32_be(decoded.payload, 0),
            abi_version: read_u32_be(decoded.payload, 4),
            slot_index: read_u32_be(decoded.payload, 8),
            node_count: read_u32_be(decoded.payload, 12),
        }),
        ControlTag::Setup => Ok(HostMsg::Setup {
            region_len: read_u64_be(decoded.payload, 0),
        }),
        ControlTag::Quit => Ok(HostMsg::Quit),
        ControlTag::SetupAck | ControlTag::Hello => Err(FrameDecodeError::UnexpectedDirection {
            tag: decoded.tag,
            expected: ControlDirection::HostToPlugin,
            actual: decoded.tag.direction(),
        }),
    }
}

/// Returns the tag carried by any complete control frame.
///
/// Unlike the directional message decoders, this accepts either registered
/// direction. It is used by lifecycle-aware run-phase checks to fault on a
/// control frame without treating it as an accepted protocol message.
///
/// # Errors
///
/// Returns [`FrameDecodeError`] when the frame bytes are empty, truncated,
/// oversized, tagged with an unknown tag, or carry a payload length that does
/// not match the tag registry.
pub fn control_frame_tag(frame: &[u8]) -> Result<ControlTag, FrameDecodeError> {
    decode_frame_any_direction(frame).map(|decoded| decoded.tag)
}

/// Reads one complete length-prefixed control frame from `reader`.
///
/// # Errors
///
/// Returns [`FrameIoError::TruncatedLengthPrefix`] or
/// [`FrameIoError::TruncatedPayload`] when the stream ends mid-frame,
/// [`FrameIoError::LengthExceedsMax`] before allocating an oversized payload, or
/// [`FrameIoError::Io`] for other stream errors.
pub fn read_control_frame<R>(reader: &mut R) -> Result<Vec<u8>, FrameIoError>
where
    R: Read,
{
    let mut length_prefix = [0; FRAME_LENGTH_PREFIX_SIZE];
    reader
        .read_exact(&mut length_prefix)
        .map_err(|error| match error.kind() {
            ErrorKind::UnexpectedEof => FrameIoError::TruncatedLengthPrefix,
            kind => FrameIoError::Io {
                operation: "read control-frame length prefix",
                kind,
            },
        })?;
    let length = u32::from_be_bytes(length_prefix);
    if length > MAX_FRAME_SIZE {
        return Err(FrameIoError::LengthExceedsMax {
            length,
            max: MAX_FRAME_SIZE,
        });
    }

    let payload_len = length as usize;
    let mut frame = Vec::with_capacity(FRAME_LENGTH_PREFIX_SIZE + payload_len);
    frame.extend_from_slice(&length_prefix);
    frame.resize(FRAME_LENGTH_PREFIX_SIZE + payload_len, 0);
    reader
        .read_exact(&mut frame[FRAME_LENGTH_PREFIX_SIZE..])
        .map_err(|error| match error.kind() {
            ErrorKind::UnexpectedEof => FrameIoError::TruncatedPayload { length },
            kind => FrameIoError::Io {
                operation: "read control-frame payload",
                kind,
            },
        })?;

    Ok(frame)
}

/// Writes and flushes a complete control frame to `writer`.
///
/// # Errors
///
/// Returns [`FrameIoError::Io`] when the underlying writer rejects the frame or
/// flush.
pub fn write_control_frame<W>(writer: &mut W, frame: &[u8]) -> Result<(), FrameIoError>
where
    W: Write,
{
    writer.write_all(frame).map_err(|error| FrameIoError::Io {
        operation: "write control frame",
        kind: error.kind(),
    })?;
    writer.flush().map_err(|error| FrameIoError::Io {
        operation: "flush control frame",
        kind: error.kind(),
    })
}

/// Runs the host side of the blocking `Hello`/`HelloAck` handshake.
///
/// This reads one plugin `Hello`, negotiates
/// `min(plugin.proto_version, config.proto_version)`, checks the shmem ABI
/// version exactly, validates the assigned slot, writes `HelloAck`, and returns
/// the negotiated values.
///
/// # Errors
///
/// Returns [`HandshakeError`] when the frame cannot be read, decoded, or
/// written; when the first plugin message is not `Hello`; when protocol
/// versions do not overlap; when the shmem ABI version differs; or when
/// `slot_index >= node_count`.
pub fn host_accept_handshake<S>(
    stream: &mut S,
    config: HostHandshakeConfig,
) -> Result<NegotiatedHandshake, HandshakeError>
where
    S: Read + Write,
{
    let frame = read_control_frame(stream).map_err(|source| HandshakeError::Io { source })?;
    let message =
        control_decode_plugin_msg(&frame).map_err(|source| HandshakeError::Decode { source })?;
    let negotiated = host_negotiate_handshake(message, config)?;
    let ack = HostMsg::HelloAck {
        proto_version: negotiated.proto_version,
        abi_version: negotiated.abi_version,
        slot_index: negotiated.slot_index,
        node_count: negotiated.node_count,
    };
    let ack = control_encode_host_msg(&ack);
    write_control_frame(stream, &ack).map_err(|source| HandshakeError::Io { source })?;
    Ok(negotiated)
}

/// Runs the plugin side of the blocking `Hello`/`HelloAck` handshake.
///
/// This writes `Hello`, blocks for one host `HelloAck`, checks that the
/// negotiated protocol version remains within the plugin-supported range,
/// checks the shmem ABI version exactly, validates `slot_index < node_count`,
/// and returns the negotiated values.
///
/// # Errors
///
/// Returns [`HandshakeError`] when the frame cannot be written, read, or
/// decoded; when the host reply is not `HelloAck`; when the negotiated protocol
/// version is outside the plugin's range; when the shmem ABI version differs;
/// or when `slot_index >= node_count`.
pub fn plugin_start_handshake<S>(
    stream: &mut S,
    config: PluginHandshakeConfig,
) -> Result<NegotiatedHandshake, HandshakeError>
where
    S: Read + Write,
{
    let hello = PluginMsg::Hello {
        proto_version: config.proto_version,
        abi_version: config.abi_version,
    };
    let hello = control_encode_plugin_msg(&hello);
    write_control_frame(stream, &hello).map_err(|source| HandshakeError::Io { source })?;

    let frame = read_control_frame(stream).map_err(|source| HandshakeError::Io { source })?;
    let message =
        control_decode_host_msg(&frame).map_err(|source| HandshakeError::Decode { source })?;
    plugin_validate_handshake_ack(message, config)
}

/// Negotiates a host-side `Hello` message without performing I/O.
///
/// # Errors
///
/// Returns [`HandshakeError`] when `message` is not `Hello`, when the protocol
/// versions do not overlap, when the shmem ABI version differs, or when the
/// host slot assignment is outside the declared node range.
pub fn host_negotiate_handshake(
    message: PluginMsg,
    config: HostHandshakeConfig,
) -> Result<NegotiatedHandshake, HandshakeError> {
    let PluginMsg::Hello {
        proto_version: plugin_proto_version,
        abi_version: plugin_abi_version,
    } = message
    else {
        return Err(HandshakeError::UnexpectedPluginMessage { message });
    };

    if plugin_proto_version < CONTROL_PROTOCOL_MIN_VERSION
        || config.proto_version < CONTROL_PROTOCOL_MIN_VERSION
    {
        return Err(HandshakeError::ProtocolVersionNoOverlap {
            plugin_max: plugin_proto_version,
            host_min: CONTROL_PROTOCOL_MIN_VERSION,
            host_max: config.proto_version,
        });
    }

    if plugin_abi_version != config.abi_version {
        return Err(HandshakeError::AbiMismatch {
            plugin_abi: plugin_abi_version,
            host_abi: config.abi_version,
        });
    }

    validate_slot_assignment(config.slot_index, config.node_count)?;

    Ok(NegotiatedHandshake {
        proto_version: plugin_proto_version.min(config.proto_version),
        abi_version: config.abi_version,
        slot_index: config.slot_index,
        node_count: config.node_count,
    })
}

/// Validates a plugin-side `HelloAck` message without performing I/O.
///
/// # Errors
///
/// Returns [`HandshakeError`] when `message` is not `HelloAck`, when the
/// negotiated protocol version is outside the plugin-supported range, when the
/// shmem ABI version differs, or when `slot_index >= node_count`.
pub fn plugin_validate_handshake_ack(
    message: HostMsg,
    config: PluginHandshakeConfig,
) -> Result<NegotiatedHandshake, HandshakeError> {
    let HostMsg::HelloAck {
        proto_version,
        abi_version,
        slot_index,
        node_count,
    } = message
    else {
        return Err(HandshakeError::UnexpectedHostMessage { message });
    };

    if proto_version < CONTROL_PROTOCOL_MIN_VERSION || proto_version > config.proto_version {
        return Err(HandshakeError::NegotiatedProtocolOutOfRange {
            negotiated: proto_version,
            plugin_min: CONTROL_PROTOCOL_MIN_VERSION,
            plugin_max: config.proto_version,
        });
    }

    if abi_version != config.abi_version {
        return Err(HandshakeError::AbiMismatch {
            plugin_abi: config.abi_version,
            host_abi: abi_version,
        });
    }

    validate_slot_assignment(slot_index, node_count)?;

    Ok(NegotiatedHandshake {
        proto_version,
        abi_version,
        slot_index,
        node_count,
    })
}

/// Sends a plugin setup-completion acknowledgement.
///
/// Callers send `status == 0` only after mapping exactly `Setup.region_len`,
/// validating the shared-memory ABI marker, and arming the wake fd.
///
/// # Errors
///
/// Returns [`SetupCompletionError::Io`] when writing or flushing the control
/// frame fails.
pub fn plugin_send_setup_ack<W>(writer: &mut W, status: u8) -> Result<(), SetupCompletionError>
where
    W: Write,
{
    let ack = control_encode_plugin_msg(&PluginMsg::SetupAck { status });
    write_control_frame(writer, &ack).map_err(|source| SetupCompletionError::Io { source })
}

/// Reads and validates the host-side setup acknowledgement before scheduling.
///
/// A successful return is the host's permission token for including the node in
/// a quantum. Any nonzero `SetupAck.status` is a setup failure.
///
/// # Errors
///
/// Returns [`SetupCompletionError`] when the frame cannot be read or decoded,
/// when the plugin sends a different message, or when `SetupAck.status` is
/// nonzero.
pub fn host_accept_setup_ack<R>(
    reader: &mut R,
) -> Result<SchedulableNodeSetup, SetupCompletionError>
where
    R: Read,
{
    let frame = read_control_frame(reader).map_err(|source| SetupCompletionError::Io { source })?;
    let message = control_decode_plugin_msg(&frame)
        .map_err(|source| SetupCompletionError::Decode { source })?;
    host_validate_setup_ack(message)
}

/// Validates a decoded plugin `SetupAck` without performing I/O.
///
/// # Errors
///
/// Returns [`SetupCompletionError::UnexpectedPluginMessage`] when `message` is
/// not `SetupAck`, or [`SetupCompletionError::NonZeroSetupAck`] when the status
/// byte is not zero.
pub fn host_validate_setup_ack(
    message: PluginMsg,
) -> Result<SchedulableNodeSetup, SetupCompletionError> {
    let PluginMsg::SetupAck { status } = message else {
        return Err(SetupCompletionError::UnexpectedPluginMessage { message });
    };

    if status != SETUP_ACK_STATUS_READY {
        return Err(SetupCompletionError::NonZeroSetupAck { status });
    }

    Ok(SchedulableNodeSetup { status })
}

fn next_lifecycle_state(
    state: ControlLifecycleState,
    event: ControlLifecycleEvent,
) -> Result<ControlLifecycleState, ControlLifecycleError> {
    if state == ControlLifecycleState::RunningViaSharedMemory {
        return match event {
            ControlLifecycleEvent::RunViaSharedMemory => {
                Ok(ControlLifecycleState::RunningViaSharedMemory)
            }
            ControlLifecycleEvent::HostQuit => Ok(ControlLifecycleState::QuitSent),
            _ => match event.control_tag() {
                Some(tag) => Err(ControlLifecycleError::ControlFrameDuringRun {
                    tag,
                    direction: tag.direction(),
                }),
                None => Err(ControlLifecycleError::UnexpectedEvent { state, event }),
            },
        };
    }

    match (state, event) {
        (
            ControlLifecycleState::Disconnected,
            ControlLifecycleEvent::ConnectUnixStreamSocketPair,
        ) => Ok(ControlLifecycleState::Connected),
        (ControlLifecycleState::Connected, ControlLifecycleEvent::PluginHello) => {
            Ok(ControlLifecycleState::HelloSent)
        }
        (ControlLifecycleState::HelloSent, ControlLifecycleEvent::HostHelloAck) => {
            Ok(ControlLifecycleState::HelloAcknowledged)
        }
        (ControlLifecycleState::HelloAcknowledged, ControlLifecycleEvent::HostSetup) => {
            Ok(ControlLifecycleState::SetupSent)
        }
        (
            ControlLifecycleState::SetupSent,
            ControlLifecycleEvent::PluginSetupAck {
                status: SETUP_ACK_STATUS_READY,
            },
        ) => Ok(ControlLifecycleState::SetupAcknowledged),
        (ControlLifecycleState::SetupSent, ControlLifecycleEvent::PluginSetupAck { status }) => {
            Err(ControlLifecycleError::NonReadySetupAck { status })
        }
        (ControlLifecycleState::SetupAcknowledged, ControlLifecycleEvent::RunViaSharedMemory) => {
            Ok(ControlLifecycleState::RunningViaSharedMemory)
        }
        _ => Err(ControlLifecycleError::UnexpectedEvent { state, event }),
    }
}

fn ensure_running_via_shared_memory(
    state: ControlLifecycleState,
) -> Result<(), ControlLifecycleError> {
    if state == ControlLifecycleState::RunningViaSharedMemory {
        Ok(())
    } else {
        Err(ControlLifecycleError::UnexpectedEvent {
            state,
            event: ControlLifecycleEvent::RunViaSharedMemory,
        })
    }
}

fn ensure_waiting_for_setup_ack(state: ControlLifecycleState) -> Result<(), ControlLifecycleError> {
    if state == ControlLifecycleState::SetupSent {
        Ok(())
    } else {
        Err(ControlLifecycleError::UnexpectedEvent {
            state,
            event: ControlLifecycleEvent::PluginSetupAck {
                status: SETUP_ACK_STATUS_READY,
            },
        })
    }
}

/// Sends a `Setup` frame and its fixed-order descriptors over a Unix socket.
///
/// The descriptors are attached as `SCM_RIGHTS` ancillary data using
/// `sendmsg`, in the RFC-defined order
/// `[shmem_fd, wake_fd, app_random_branch_plan_fd]`.
///
/// # Errors
///
/// Returns [`DescriptorHandoverError::Io`] when `sendmsg` fails,
/// [`DescriptorHandoverError::ShortWrite`] if the stream accepts only part of
/// the frame, or [`DescriptorHandoverError::MalformedAncillary`] if the local
/// ancillary buffer cannot represent the fixed descriptor list.
#[cfg(unix)]
pub fn send_setup_with_descriptors(
    socket_fd: RawFd,
    region_len: u64,
    descriptors: SetupDescriptorFds,
) -> Result<(), DescriptorHandoverError> {
    let frame = control_encode_host_msg(&HostMsg::Setup { region_len });
    let fds = [
        descriptors.shmem_fd,
        descriptors.wake_fd,
        descriptors.app_random_branch_plan_fd,
    ];
    send_frame_with_fds(socket_fd, &frame, &fds)
}

/// Receives a `Setup` frame and its fixed-order descriptors from a Unix socket.
///
/// The frame must carry exactly three `SCM_RIGHTS` descriptors. The returned
/// descriptors are owned, marked close-on-exec, and returned in the RFC-defined
/// order: shmem first, wake second, immutable app-random branch plan third.
///
/// # Errors
///
/// Returns [`DescriptorHandoverError`] when the socket closes early, the
/// ancillary data is truncated or malformed, the descriptor count is not
/// exactly three, or the frame does not decode to [`HostMsg::Setup`].
#[cfg(unix)]
pub fn recv_setup_with_descriptors(
    socket_fd: RawFd,
) -> Result<ReceivedSetup, DescriptorHandoverError> {
    let mut length_prefix = [0; FRAME_LENGTH_PREFIX_SIZE];
    let raw_fds = recv_setup_prefix_and_fds(socket_fd, &mut length_prefix)?;
    let descriptors = setup_descriptors_from_raw_fds(raw_fds)?;

    let length = u32::from_be_bytes(length_prefix);
    if length > MAX_FRAME_SIZE {
        return Err(DescriptorHandoverError::Decode {
            source: FrameDecodeError::LengthExceedsMax {
                length,
                max: MAX_FRAME_SIZE,
            },
        });
    }

    let payload_len = length as usize;
    let mut frame = Vec::with_capacity(FRAME_LENGTH_PREFIX_SIZE + payload_len);
    frame.extend_from_slice(&length_prefix);
    frame.resize(FRAME_LENGTH_PREFIX_SIZE + payload_len, 0);
    recv_exact_fd(
        socket_fd,
        &mut frame[FRAME_LENGTH_PREFIX_SIZE..],
        "receive setup frame payload",
    )?;

    match control_decode_host_msg(&frame)
        .map_err(|source| DescriptorHandoverError::Decode { source })?
    {
        HostMsg::Setup { region_len } => Ok(ReceivedSetup {
            region_len,
            descriptors,
        }),
        message => Err(DescriptorHandoverError::UnexpectedMessage { message }),
    }
}

/// The runtime data plane used after protocol setup completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeDataPlane {
    /// Runtime delivery uses the shared-memory region, not control frames.
    SharedMemory,
}

/// The control/data split required for deterministic runtime injection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeDataPlaneContract {
    /// The transport that carries runtime frame and clock data.
    pub runtime_data_plane: RuntimeDataPlane,
    /// Whether the control channel carries runtime frame payloads.
    pub control_channel_carries_runtime_frames: bool,
    /// Whether the control channel carries frame delivery icounts.
    pub control_channel_carries_delivery_icounts: bool,
    /// Whether the control channel is silent between setup completion and quit.
    pub control_channel_silent_between_setup_ack_and_quit: bool,
}

/// The protocol-level Contract B boundary.
pub const RUNTIME_DATA_PLANE_CONTRACT: RuntimeDataPlaneContract = RuntimeDataPlaneContract {
    runtime_data_plane: RuntimeDataPlane::SharedMemory,
    control_channel_carries_runtime_frames: false,
    control_channel_carries_delivery_icounts: false,
    control_channel_silent_between_setup_ack_and_quit: true,
};

#[cfg(unix)]
struct AncillaryBuffer {
    storage: [libc::cmsghdr; ANCILLARY_STORAGE_HEADERS],
    len: usize,
}

#[cfg(unix)]
impl AncillaryBuffer {
    fn for_single_cmsg_fd_capacity(fd_capacity: usize) -> Result<Self, DescriptorHandoverError> {
        let payload_len = fd_capacity
            .checked_mul(std::mem::size_of::<RawFd>())
            .ok_or(DescriptorHandoverError::MalformedAncillary {
                reason: "descriptor payload length overflow",
            })?;
        let len = cmsg_space(payload_len)?;
        Self::with_len(len)
    }

    fn for_split_cmsg_fd_capacity(fd_capacity: usize) -> Result<Self, DescriptorHandoverError> {
        let fd_size = std::mem::size_of::<RawFd>();
        let packed_payload_len = fd_capacity.checked_mul(fd_size).ok_or(
            DescriptorHandoverError::MalformedAncillary {
                reason: "descriptor payload length overflow",
            },
        )?;
        let packed_len = cmsg_space(packed_payload_len)?;
        let split_len = fd_capacity.checked_mul(cmsg_space(fd_size)?).ok_or(
            DescriptorHandoverError::MalformedAncillary {
                reason: "ancillary split-header length overflow",
            },
        )?;

        Self::with_len(packed_len.max(split_len))
    }

    fn with_len(len: usize) -> Result<Self, DescriptorHandoverError> {
        let byte_capacity = ANCILLARY_STORAGE_HEADERS
            .checked_mul(std::mem::size_of::<libc::cmsghdr>())
            .ok_or(DescriptorHandoverError::MalformedAncillary {
                reason: "ancillary storage length overflow",
            })?;
        if len > byte_capacity {
            return Err(DescriptorHandoverError::MalformedAncillary {
                reason: "ancillary storage too small",
            });
        }

        Ok(Self {
            storage: std::array::from_fn(|_| empty_cmsghdr()),
            len,
        })
    }

    fn as_mut_ptr(&mut self) -> *mut libc::c_void {
        self.storage.as_mut_ptr().cast::<libc::c_void>()
    }
}

#[cfg(unix)]
fn empty_cmsghdr() -> libc::cmsghdr {
    libc::cmsghdr {
        cmsg_len: 0,
        cmsg_level: 0,
        cmsg_type: 0,
    }
}

#[cfg(unix)]
fn send_frame_with_fds(
    socket_fd: RawFd,
    frame: &[u8],
    fds: &[RawFd; SETUP_DESCRIPTOR_COUNT],
) -> Result<(), DescriptorHandoverError> {
    let mut iov = libc::iovec {
        iov_base: frame.as_ptr().cast::<libc::c_void>().cast_mut(),
        iov_len: frame.len(),
    };
    let mut control = AncillaryBuffer::for_single_cmsg_fd_capacity(fds.len())?;
    let mut message = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr(),
        msg_controllen: msg_control_len(control.len)?,
        msg_flags: 0,
    };

    // SAFETY: `message` contains a live ancillary buffer and a valid controllen.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if cmsg.is_null() {
        return Err(DescriptorHandoverError::MalformedAncillary {
            reason: "missing first control-message header",
        });
    }

    let payload_len = fds.len() * std::mem::size_of::<RawFd>();
    let cmsg_len = cmsg_len(payload_len)?;
    // SAFETY: `cmsg` points into live aligned `control` storage, and `payload_len` exactly covers `fds`.
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = cmsg_len as _;
        std::ptr::copy_nonoverlapping(
            fds.as_ptr(),
            libc::CMSG_DATA(cmsg).cast::<RawFd>(),
            fds.len(),
        );
    }

    message.msg_controllen = msg_control_len(cmsg_space(payload_len)?)?;
    let sent = loop {
        // SAFETY: `message` references live frame and ancillary buffers for this syscall.
        let result = unsafe { libc::sendmsg(socket_fd, &message, send_flags()) };
        if result < 0 {
            let errno = last_errno_value();
            if errno == libc::EINTR {
                continue;
            }
            return Err(DescriptorHandoverError::Io {
                operation: "send setup frame with descriptors",
                errno,
            });
        }
        break result;
    };

    let actual =
        usize::try_from(sent).map_err(|_| DescriptorHandoverError::MalformedAncillary {
            reason: "negative send length after success",
        })?;
    if actual != frame.len() {
        return Err(DescriptorHandoverError::ShortWrite {
            expected: frame.len(),
            actual,
        });
    }

    Ok(())
}

#[cfg(unix)]
fn recv_setup_prefix_and_fds(
    socket_fd: RawFd,
    length_prefix: &mut [u8; FRAME_LENGTH_PREFIX_SIZE],
) -> Result<Vec<RawFd>, DescriptorHandoverError> {
    let mut iov = libc::iovec {
        iov_base: length_prefix.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: length_prefix.len(),
    };
    let mut control = AncillaryBuffer::for_split_cmsg_fd_capacity(SETUP_DESCRIPTOR_RECV_CAPACITY)?;
    let mut message = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr(),
        msg_controllen: msg_control_len(control.len)?,
        msg_flags: 0,
    };

    let received = loop {
        // SAFETY: `message` references live prefix and ancillary buffers for this syscall.
        let result = unsafe { libc::recvmsg(socket_fd, &mut message, 0) };
        if result < 0 {
            let errno = last_errno_value();
            if errno == libc::EINTR {
                continue;
            }
            return Err(DescriptorHandoverError::Io {
                operation: "receive setup length prefix and descriptors",
                errno,
            });
        }
        break result;
    };

    if received == 0 {
        return Err(DescriptorHandoverError::PeerClosed {
            operation: "receive setup length prefix and descriptors",
        });
    }

    let received =
        usize::try_from(received).map_err(|_| DescriptorHandoverError::MalformedAncillary {
            reason: "negative receive length after success",
        })?;
    let fds = parse_scm_rights_fds(&message)?;
    if received < length_prefix.len()
        && let Err(error) = recv_exact_fd(
            socket_fd,
            &mut length_prefix[received..],
            "receive setup length prefix remainder",
        )
    {
        close_raw_fds(fds);
        return Err(error);
    }

    Ok(fds)
}

#[cfg(unix)]
fn recv_exact_fd(
    socket_fd: RawFd,
    mut buffer: &mut [u8],
    operation: &'static str,
) -> Result<(), DescriptorHandoverError> {
    while !buffer.is_empty() {
        // SAFETY: `buffer` is a live writable byte slice for this syscall.
        let received = unsafe {
            libc::recv(
                socket_fd,
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                buffer.len(),
                0,
            )
        };
        if received < 0 {
            let errno = last_errno_value();
            if errno == libc::EINTR {
                continue;
            }
            return Err(DescriptorHandoverError::Io { operation, errno });
        }
        if received == 0 {
            return Err(DescriptorHandoverError::PeerClosed { operation });
        }

        let received =
            usize::try_from(received).map_err(|_| DescriptorHandoverError::MalformedAncillary {
                reason: "negative receive length after success",
            })?;
        let remaining =
            buffer
                .get_mut(received..)
                .ok_or(DescriptorHandoverError::MalformedAncillary {
                    reason: "receive length exceeded requested buffer",
                })?;
        buffer = remaining;
    }

    Ok(())
}

#[cfg(unix)]
fn parse_scm_rights_fds(message: &libc::msghdr) -> Result<Vec<RawFd>, DescriptorHandoverError> {
    let mut fds = Vec::new();
    let truncated = message.msg_flags & libc::MSG_CTRUNC != 0;
    // SAFETY: `message` contains the live ancillary buffer filled by `recvmsg`.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !cmsg.is_null() {
        // SAFETY: `cmsg` was returned by `CMSG_FIRSTHDR`/`CMSG_NXTHDR` for `message`.
        let header = unsafe { &*cmsg };
        if header.cmsg_level == libc::SOL_SOCKET
            && header.cmsg_type == libc::SCM_RIGHTS
            && let Err(error) = append_rights_fds(header, cmsg, &mut fds)
        {
            close_raw_fds(fds);
            return Err(error);
        }
        // SAFETY: `cmsg` is the current header for `message`.
        cmsg = unsafe { libc::CMSG_NXTHDR(message, cmsg) };
    }

    if truncated {
        close_raw_fds(fds);
        return Err(DescriptorHandoverError::AncillaryTruncated);
    }

    Ok(fds)
}

#[cfg(unix)]
fn append_rights_fds(
    header: &libc::cmsghdr,
    cmsg: *mut libc::cmsghdr,
    fds: &mut Vec<RawFd>,
) -> Result<(), DescriptorHandoverError> {
    let header_len = cmsg_len(0)?;
    let cmsg_len = cmsghdr_len(header)?;
    if cmsg_len < header_len {
        return Err(DescriptorHandoverError::MalformedAncillary {
            reason: "control-message length shorter than header",
        });
    }

    let data_len = cmsg_len - header_len;
    let fd_size = std::mem::size_of::<RawFd>();
    if !data_len.is_multiple_of(fd_size) {
        return Err(DescriptorHandoverError::MalformedAncillary {
            reason: "descriptor payload is not fd-aligned",
        });
    }

    let count = data_len / fd_size;
    // SAFETY: `cmsg` is a valid `SCM_RIGHTS` header for this message.
    let data = unsafe { libc::CMSG_DATA(cmsg).cast::<RawFd>() };
    for index in 0..count {
        // SAFETY: `data_len` is a whole number of `RawFd` elements, and `index` is in bounds.
        let fd = unsafe { *data.add(index) };
        fds.push(fd);
    }

    Ok(())
}

#[cfg(unix)]
fn setup_descriptors_from_raw_fds(
    fds: Vec<RawFd>,
) -> Result<ReceivedSetupDescriptors, DescriptorHandoverError> {
    let [shmem_fd, wake_fd, app_random_branch_plan_fd] =
        match <[RawFd; SETUP_DESCRIPTOR_COUNT]>::try_from(fds) {
            Ok(fds) => fds,
            Err(fds) => {
                let count = fds.len();
                close_raw_fds(fds);
                return Err(DescriptorHandoverError::WrongDescriptorCount { count });
            }
        };

    if let Err(error) = set_cloexec_on_raw_fd(shmem_fd) {
        close_raw_fds(vec![shmem_fd, wake_fd, app_random_branch_plan_fd]);
        return Err(error);
    }
    if let Err(error) = set_cloexec_on_raw_fd(wake_fd) {
        close_raw_fds(vec![shmem_fd, wake_fd, app_random_branch_plan_fd]);
        return Err(error);
    }
    if let Err(error) = set_cloexec_on_raw_fd(app_random_branch_plan_fd) {
        close_raw_fds(vec![shmem_fd, wake_fd, app_random_branch_plan_fd]);
        return Err(error);
    }

    // SAFETY: the descriptors came from `SCM_RIGHTS` and are uniquely wrapped here.
    let descriptors = unsafe {
        ReceivedSetupDescriptors {
            shmem_fd: OwnedFd::from_raw_fd(shmem_fd),
            wake_fd: OwnedFd::from_raw_fd(wake_fd),
            app_random_branch_plan_fd: OwnedFd::from_raw_fd(app_random_branch_plan_fd),
        }
    };
    Ok(descriptors)
}

#[cfg(unix)]
fn close_raw_fds(fds: Vec<RawFd>) {
    for fd in fds {
        // SAFETY: each descriptor came from `SCM_RIGHTS` and is uniquely owned on this error path.
        unsafe {
            drop(OwnedFd::from_raw_fd(fd));
        }
    }
}

#[cfg(unix)]
fn set_cloexec_on_raw_fd(fd: RawFd) -> Result<(), DescriptorHandoverError> {
    // SAFETY: `fcntl(F_GETFD)` reads descriptor flags for a live raw fd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(DescriptorHandoverError::Io {
            operation: "read setup descriptor flags",
            errno: last_errno_value(),
        });
    }

    // SAFETY: `fcntl(F_SETFD)` updates descriptor flags for a live raw fd.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if result < 0 {
        return Err(DescriptorHandoverError::Io {
            operation: "mark setup descriptor close-on-exec",
            errno: last_errno_value(),
        });
    }

    Ok(())
}

#[cfg(unix)]
fn cmsg_space(payload_len: usize) -> Result<usize, DescriptorHandoverError> {
    let payload_len =
        u32::try_from(payload_len).map_err(|_| DescriptorHandoverError::MalformedAncillary {
            reason: "control-message payload length exceeds c_uint",
        })?;
    // SAFETY: `payload_len` is a byte count converted to the libc CMSG width.
    Ok(unsafe { libc::CMSG_SPACE(payload_len) as usize })
}

#[cfg(unix)]
fn cmsg_len(payload_len: usize) -> Result<usize, DescriptorHandoverError> {
    let payload_len =
        u32::try_from(payload_len).map_err(|_| DescriptorHandoverError::MalformedAncillary {
            reason: "control-message payload length exceeds c_uint",
        })?;
    // SAFETY: `payload_len` is a byte count converted to the libc CMSG width.
    Ok(unsafe { libc::CMSG_LEN(payload_len) as usize })
}

#[cfg(all(
    unix,
    any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "watchos"
    )
))]
fn msg_control_len(len: usize) -> Result<MsgControlLen, DescriptorHandoverError> {
    len.try_into()
        .map_err(|_| DescriptorHandoverError::MalformedAncillary {
            reason: "ancillary length exceeds msg_controllen",
        })
}

#[cfg(all(
    unix,
    not(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "watchos"
    ))
))]
fn msg_control_len(len: usize) -> Result<MsgControlLen, DescriptorHandoverError> {
    Ok(len)
}

#[cfg(all(
    unix,
    any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "watchos"
    )
))]
fn cmsghdr_len(header: &libc::cmsghdr) -> Result<usize, DescriptorHandoverError> {
    Ok(header.cmsg_len as usize)
}

#[cfg(all(
    unix,
    not(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "watchos"
    ))
))]
fn cmsghdr_len(header: &libc::cmsghdr) -> Result<usize, DescriptorHandoverError> {
    Ok(header.cmsg_len)
}

#[cfg(all(
    unix,
    any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "watchos"
    )
))]
fn send_flags() -> libc::c_int {
    libc::MSG_NOSIGNAL
}

#[cfg(all(
    unix,
    not(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "watchos"
    ))
))]
fn send_flags() -> libc::c_int {
    0
}

#[cfg(unix)]
fn last_errno_value() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .map_or(0, |errno| errno)
}

fn validate_slot_assignment(slot_index: u32, node_count: u32) -> Result<(), HandshakeError> {
    if slot_index < node_count {
        Ok(())
    } else {
        Err(HandshakeError::InvalidSlot {
            slot_index,
            node_count,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DecodedFrame<'a> {
    tag: ControlTag,
    payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FieldValue {
    U8(u8),
    U32(u32),
    U64(u64),
}

fn encode_frame(tag: ControlTag, fields: &[FieldValue]) -> Vec<u8> {
    let payload_len: usize = fields
        .iter()
        .map(|field| match field {
            FieldValue::U8(_) => 1,
            FieldValue::U32(_) => 4,
            FieldValue::U64(_) => 8,
        })
        .sum();
    debug_assert_eq!(payload_len, tag.payload_len());
    debug_assert!(FRAME_TAG_SIZE + payload_len <= MAX_FRAME_SIZE as usize);

    let frame_len = FRAME_TAG_SIZE + payload_len;
    let mut frame = Vec::with_capacity(FRAME_LENGTH_PREFIX_SIZE + frame_len);
    frame.extend_from_slice(&(frame_len as u32).to_be_bytes());
    frame.push(tag.wire_value());
    for field in fields {
        match field {
            FieldValue::U8(value) => frame.push(*value),
            FieldValue::U32(value) => frame.extend_from_slice(&value.to_be_bytes()),
            FieldValue::U64(value) => frame.extend_from_slice(&value.to_be_bytes()),
        }
    }
    frame
}

fn decode_frame(
    frame: &[u8],
    expected_direction: ControlDirection,
) -> Result<DecodedFrame<'_>, FrameDecodeError> {
    let decoded = decode_frame_any_direction(frame)?;
    let actual_direction = decoded.tag.direction();
    if actual_direction != expected_direction {
        return Err(FrameDecodeError::UnexpectedDirection {
            tag: decoded.tag,
            expected: expected_direction,
            actual: actual_direction,
        });
    }

    Ok(decoded)
}

fn decode_frame_any_direction(frame: &[u8]) -> Result<DecodedFrame<'_>, FrameDecodeError> {
    if frame.is_empty() {
        return Err(FrameDecodeError::EmptyFrame);
    }
    if frame.len() < FRAME_LENGTH_PREFIX_SIZE {
        return Err(FrameDecodeError::TruncatedLengthPrefix {
            actual: frame.len(),
        });
    }

    let declared = read_u32_be(frame, 0);
    if declared > MAX_FRAME_SIZE {
        return Err(FrameDecodeError::LengthExceedsMax {
            length: declared,
            max: MAX_FRAME_SIZE,
        });
    }

    let declared = declared as usize;
    let actual = frame.len() - FRAME_LENGTH_PREFIX_SIZE;
    if actual < declared {
        return Err(FrameDecodeError::TruncatedPayload { declared, actual });
    }
    if actual > declared {
        return Err(FrameDecodeError::TrailingBytes { declared, actual });
    }
    if declared == 0 {
        return Err(FrameDecodeError::MissingTag);
    }

    let tag_byte = frame[FRAME_LENGTH_PREFIX_SIZE];
    let tag = ControlTag::from_wire_value(tag_byte)
        .ok_or(FrameDecodeError::UnknownTag { tag: tag_byte })?;

    let payload = &frame[FRAME_LENGTH_PREFIX_SIZE + FRAME_TAG_SIZE..];
    let expected_payload_len = tag.payload_len();
    if payload.len() < expected_payload_len {
        return Err(FrameDecodeError::PayloadTooShort {
            tag,
            expected: expected_payload_len,
            actual: payload.len(),
        });
    }
    if payload.len() > expected_payload_len {
        return Err(FrameDecodeError::PayloadTooLong {
            tag,
            expected: expected_payload_len,
            actual: payload.len(),
        });
    }

    Ok(DecodedFrame { tag, payload })
}

fn read_u32_be(bytes: &[u8], offset: usize) -> u32 {
    let mut out = [0; 4];
    out.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_be_bytes(out)
}

fn read_u64_be(bytes: &[u8], offset: usize) -> u64 {
    let mut out = [0; 8];
    out.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_be_bytes(out)
}
