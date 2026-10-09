//! Owned adapters for deterministic host-side device and clock models.
//!
//! Models retain their existing continuation codecs. Qualified host profiles
//! execute authentic staged requests and pending events within exact grants,
//! preserving original input, publication and native receipt custody. The
//! controlled reference child provides a distinct coarse quantized profile.

mod host;
mod inventory;
mod reference_device;

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
