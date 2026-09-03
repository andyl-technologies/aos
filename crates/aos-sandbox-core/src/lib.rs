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

pub mod capability;
pub mod format;
pub mod identity;
pub mod model;
pub mod resources;
pub mod selector;
pub mod state;
pub mod version;

pub use capability::{
    AttenuationError, AttenuationRequest, AuthorizationContext, AuthorizationError,
    CapabilityDraft, CapabilityRecord, CapabilityValidationError, ChannelBinding, DelegationLimits,
    Grant, InvalidGrant,
};
pub use format::{CanonicalCborError, DecodeLimits, descriptor_for_bytes, validate_canonical_cbor};
pub use identity::{
    AttachmentId, AttachmentSlotId, AuditId, CacheDomainId, CapabilityId, ExecutionId, ExportId,
    GrantId, IncarnationId, IssuerId, LeaseId, NetworkEndpointId, NodeId, OperationId, PrincipalId,
    ProjectId, ResourceId, RestoreScopeId, RevocationScopeId, SandboxId, SecretId, ServiceId,
    SnapshotId, TrustScopeId, ViewId,
};
pub use resources::{
    AccountingError, AncestryAdmissionError, ReservationClass, ResourceAccount, ResourceBudget,
    ResourceCeilings, ResourceDimension, ResourceLimit, ResourceVector,
};
pub use selector::{
    FeatureRef, MediaType, ObjectDescriptor, ObjectDigest, Operation, OperationSet, PathName,
    RelativePath, ResourceKind, Selector,
};
pub use version::{
    AssignmentEpoch, DesiredGeneration, NamespaceGeneration, ObservationSequence, Revision,
};
