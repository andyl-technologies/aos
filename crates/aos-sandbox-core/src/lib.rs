//! Defines the portable model shared by AOS sandbox components.
//!
//! This crate owns logical identities, fencing generations, policy math,
//! lifecycle state machines, and portable object schemas. It deliberately has
//! no dependency on Linux system calls, D-Bus, storage commands, or a runtime
//! backend. Privileged services consume validated values from this crate but
//! do not parse public requests themselves.
//!
//! The [`identity`] module defines opaque 128-bit identifiers. The [`version`]
//! module defines monotonic counters used to reject stale work.

pub mod identity;
pub mod resources;
pub mod state;
pub mod version;

pub use identity::{
    AttachmentId, ExecutionId, ExportId, IncarnationId, NodeId, OperationId, ProjectId, SandboxId,
    SnapshotId, ViewId,
};
pub use version::{
    AssignmentEpoch, DesiredGeneration, NamespaceGeneration, ObservationSequence, Revision,
};
