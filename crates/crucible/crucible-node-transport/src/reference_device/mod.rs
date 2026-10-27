//! Controlled child-process device with bounded quantized output custody.
//!
//! This reference profile transforms byte batches into a stateful rolling
//! checksum. [`ReferenceDevice`] owns the private socket and actual child
//! lifecycle; [`DeviceReceipt`] preserves an immutable input cut, a fixed
//! publication boundary and acknowledged application-level park. Host admission
//! must supply causal authorization and bind these receipts to the world.
//! Neither the private protocol nor this device implements a KVM clock or
//! claims pause of an autonomous physical device.

mod child;
mod process;
mod progress;
mod protocol;
mod supervision;

pub use child::serve;
pub use process::{DeviceStatus, ReferenceDevice};
pub use progress::{NativeProgressPredecessor, NativeProgressRecord, serve_with_progress};
pub use protocol::{DeviceGrant, DeviceOutput, DeviceReceipt, MAX_INPUT_BYTES};

pub use supervision::{
    MAX_SUPERVISED_DEVICES, SupervisedDevice, acknowledge_supervised_containment,
    poll_supervised_reclamation, supervised_devices,
};
