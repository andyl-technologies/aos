//! HTTP/2 clients and transport-independent Crucible control interfaces.
//!
//! Spec index: RFC-0010 files 21.
//!
//! Module map: client owns typed request dispatch, RPC receivers, and debugger
//! operations. Local stream traits let server-side adapters implement the same
//! interface without pulling server or QEMU realization code into this crate.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod client;
pub use client::{
    ClientControlStream, ClientWatchStream, ControlClient, ControlClientError, ControlClientFuture,
    DebugControllerAccess, DebugControllerAcquisition, InProcessLifecycleControlStream,
    RpcControlClient, RpcControlStream, RpcEndpoint, RpcMutualTlsConfig, RpcTransportProtocol,
    RpcWatchStream, WritableDebugBranch, assert_shared_wire_model,
};
pub use crucible_control_api::{
    DebugLandedRuntimeCoordinate, DebugRelayChunk, DebugRelayId, DebugRepositionResult,
    LifecycleResourceLimit,
};

pub use client::{LocalControlStream, LocalWatchStream};
