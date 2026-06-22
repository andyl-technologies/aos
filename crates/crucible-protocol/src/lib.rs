//! `crucible-protocol` owns the host/plugin wire protocol.
//!
//! Spec index: RFC-0010 files 14.
//!
//! This L1 crate will hold the framed IPC messages, version fields,
//! encode/decode routines, and golden vectors specified by its indexed RFC-0010
//! file. It operates over owned buffers and does not own the shared-memory
//! transport or scheduler semantics.
//!
//! Module map: the crate root currently reserves the host/plugin protocol
//! boundary; future modules will split frame headers, message bodies, codecs,
//! and golden vectors.
//!
//! Wire-format sketch:
//!
//! ```text
//! frame-header(version, kind, length)
//! payload-bytes
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

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
