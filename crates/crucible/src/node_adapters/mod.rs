//! Owned host-model adapters and authenticated native node preparation.
//!
//! Models retain their existing continuation codecs. Qualified host profiles
//! execute authentic staged requests and pending events within exact grants,
//! preserving original input, publication and native receipt custody. The
//! controlled reference child provides a distinct coarse quantized profile.
//! Native gem5 preparation retains real resources beneath a qualification gate.

pub mod gem5;
mod host;
mod inventory;
mod reference_device;
mod scripted_source;

pub use scripted_source::{
    MAXIMUM_SCRIPTED_REQUESTS, ScriptedRequest, ScriptedRequestKind, ScriptedSource,
};

pub use host::{
    HOST_EXACT_PROFILE, HOST_PHYSICAL_PAUSE_PROFILE, HOST_PRESERVATION_PROFILE,
    HostContinuationInventory, HostModel, HostModelNode, HostModelQualification,
    HostModelResources, host_clock_initial_bytes, validate_host_continuation,
};
pub use inventory::{CurrentPort, CurrentPortKind, CurrentWorldInventory, CurrentWorldParticipant};

pub use reference_device::{
    REFERENCE_DEVICE_QUANTIZED_PROFILE, ReferenceDeviceNode, ReferenceDeviceQualification,
    reference_device_initial_bytes,
};
