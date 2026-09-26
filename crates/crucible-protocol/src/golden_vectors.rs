//! Frozen protocol golden vectors.
//!
//! This module is the ABI-conformance corpus for the control protocol frame
//! codec. The vectors are deliberately literal byte arrays, not generated from
//! the encoder, so a protocol-version bump forces a conscious regeneration pass.

use crate::{
    CONTROL_PROTOCOL_VERSION, ControlDirection, ControlTag, HostMsg, PluginMsg,
    SETUP_ACK_STATUS_READY,
};

/// Control-protocol version for which the golden-vector corpus was generated.
///
/// This constant is intentionally a literal. Tests assert it equals
/// [`CONTROL_PROTOCOL_VERSION`] so a version bump fails until these vectors are
/// regenerated and this constant is updated.
pub const GOLDEN_VECTOR_PROTOCOL_VERSION: u32 = 3;

/// Regeneration rule for the protocol golden-vector corpus.
pub const GOLDEN_VECTOR_REGENERATION_RULE: &str =
    "Regenerate every protocol golden vector whenever CONTROL_PROTOCOL_VERSION changes.";

const GOLDEN_VECTOR_ABI_VERSION: u32 = 1;
const GOLDEN_VECTOR_SLOT_INDEX: u32 = 7;
const GOLDEN_VECTOR_NODE_COUNT: u32 = 32;
const GOLDEN_VECTOR_REGION_LEN: u64 = 450_560;

/// One frozen control-protocol golden vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlGoldenVector {
    /// Stable corpus name.
    pub name: &'static str,
    /// Control-protocol version the vector belongs to.
    pub protocol_version: u32,
    /// Direction in which the frame is valid.
    pub direction: ControlDirection,
    /// Control tag carried by the frame.
    pub tag: ControlTag,
    /// Structured message represented by the frame.
    pub message: ControlGoldenVectorMessage,
    /// Complete frame bytes, including the four-byte length prefix and tag.
    pub frame: &'static [u8],
}

/// Structured message represented by a golden vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlGoldenVectorMessage {
    /// Plugin-to-host `Hello`.
    Hello {
        /// Highest control-protocol version offered by the plugin.
        proto_version: u32,
        /// Shared-memory ABI version offered by the plugin.
        abi_version: u32,
    },
    /// Host-to-plugin `HelloAck`.
    HelloAck {
        /// Negotiated control-protocol version.
        proto_version: u32,
        /// Shared-memory ABI version accepted by the host.
        abi_version: u32,
        /// Shared-memory node slot assigned by the host.
        slot_index: u32,
        /// Total node slots in the shared-memory region.
        node_count: u32,
    },
    /// Host-to-plugin `Setup` payload.
    SetupPayload {
        /// Total byte length of the shared-memory region to map.
        region_len: u64,
    },
    /// Plugin-to-host `SetupAck`.
    SetupAck {
        /// Setup acknowledgement status.
        status: u8,
    },
    /// Host-to-plugin graceful shutdown request.
    Quit,
}

impl ControlGoldenVectorMessage {
    /// Returns this vector message as a plugin-to-host message when applicable.
    #[must_use]
    pub const fn plugin_msg(self) -> Option<PluginMsg> {
        match self {
            Self::Hello {
                proto_version,
                abi_version,
            } => Some(PluginMsg::Hello {
                proto_version,
                abi_version,
            }),
            Self::SetupAck { status } => Some(PluginMsg::SetupAck { status }),
            Self::HelloAck { .. } | Self::SetupPayload { .. } | Self::Quit => None,
        }
    }

    /// Returns this vector message as a host-to-plugin message when applicable.
    #[must_use]
    pub const fn host_msg(self) -> Option<HostMsg> {
        match self {
            Self::HelloAck {
                proto_version,
                abi_version,
                slot_index,
                node_count,
            } => Some(HostMsg::HelloAck {
                proto_version,
                abi_version,
                slot_index,
                node_count,
            }),
            Self::SetupPayload { region_len } => Some(HostMsg::Setup { region_len }),
            Self::Quit => Some(HostMsg::Quit),
            Self::Hello { .. } | Self::SetupAck { .. } => None,
        }
    }
}

/// Frozen golden-vector corpus in stable ABI-conformance order.
pub const GOLDEN_CONTROL_VECTORS: [ControlGoldenVector; 5] = [
    ControlGoldenVector {
        name: "hello",
        protocol_version: GOLDEN_VECTOR_PROTOCOL_VERSION,
        direction: ControlDirection::PluginToHost,
        tag: ControlTag::Hello,
        message: ControlGoldenVectorMessage::Hello {
            proto_version: GOLDEN_VECTOR_PROTOCOL_VERSION,
            abi_version: GOLDEN_VECTOR_ABI_VERSION,
        },
        frame: &[0, 0, 0, 9, 0xF0, 0, 0, 0, 3, 0, 0, 0, 1],
    },
    ControlGoldenVector {
        name: "hello-ack",
        protocol_version: GOLDEN_VECTOR_PROTOCOL_VERSION,
        direction: ControlDirection::HostToPlugin,
        tag: ControlTag::HelloAck,
        message: ControlGoldenVectorMessage::HelloAck {
            proto_version: GOLDEN_VECTOR_PROTOCOL_VERSION,
            abi_version: GOLDEN_VECTOR_ABI_VERSION,
            slot_index: GOLDEN_VECTOR_SLOT_INDEX,
            node_count: GOLDEN_VECTOR_NODE_COUNT,
        },
        frame: &[
            0, 0, 0, 17, 0xF1, 0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0, 32,
        ],
    },
    ControlGoldenVector {
        name: "setup-payload",
        protocol_version: GOLDEN_VECTOR_PROTOCOL_VERSION,
        direction: ControlDirection::HostToPlugin,
        tag: ControlTag::Setup,
        message: ControlGoldenVectorMessage::SetupPayload {
            region_len: GOLDEN_VECTOR_REGION_LEN,
        },
        frame: &[0, 0, 0, 9, 0x01, 0, 0, 0, 0, 0, 6, 0xE0, 0],
    },
    ControlGoldenVector {
        name: "setup-ack",
        protocol_version: GOLDEN_VECTOR_PROTOCOL_VERSION,
        direction: ControlDirection::PluginToHost,
        tag: ControlTag::SetupAck,
        message: ControlGoldenVectorMessage::SetupAck {
            status: SETUP_ACK_STATUS_READY,
        },
        frame: &[0, 0, 0, 2, 0x02, 0],
    },
    ControlGoldenVector {
        name: "quit",
        protocol_version: GOLDEN_VECTOR_PROTOCOL_VERSION,
        direction: ControlDirection::HostToPlugin,
        tag: ControlTag::Quit,
        message: ControlGoldenVectorMessage::Quit,
        frame: &[0, 0, 0, 1, 0x12],
    },
];

const _: () = assert!(GOLDEN_VECTOR_PROTOCOL_VERSION == CONTROL_PROTOCOL_VERSION);
