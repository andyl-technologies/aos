//! `crucible-protocol` owns the host/plugin wire protocol.
//!
//! Spec index: RFC-0010 files 14.
//!
//! This L1 crate owns the framed IPC message constants, version fields,
//! encode/decode routines, and golden vectors specified by its indexed RFC-0010
//! file. It operates over owned buffers and does not own the shared-memory
//! transport or scheduler semantics.
//!
//! Module map: the crate root owns the frame-format constants, closed tag
//! registry, and control/data split contract. Future modules will split message
//! bodies, codecs, descriptor passing, and golden vectors.
//!
//! Wire-format:
//!
//! ```text
//! offset  size  field
//! 0       4     length: u32 big-endian, counting tag + payload bytes
//! 4       1     tag: u8 from the closed ControlTag registry
//! 5       N     payload bytes, tag-specific and big-endian for integers
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

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
