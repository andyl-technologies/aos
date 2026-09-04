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

pub mod assignment;
pub mod broker_authorization;
pub mod capability;
pub mod crypto;
pub mod format;
pub mod identity;
pub mod model;
pub mod ownership_lease;
pub mod registry;
pub mod resources;
pub mod selector;
pub mod state;
pub mod version;

pub use assignment::CanonicalAssignmentManifestV1;
pub use broker_authorization::{
    BrokerArgumentCommitment, BrokerAssignment, BrokerAudience, BrokerAuthorizationPlan,
    BrokerGrant, BrokerGrantTarget, BrokerPlanExpectation, BrokerPlanRequest,
    BrokerPlanTrustAnchor, BrokerPlanVerificationError, BrokerResourceHandle, BrokerVerb,
    InvalidBrokerAuthorizationPlan, MatchedBrokerRequest, VerifiedBrokerPlan, verify_broker_plan,
};
pub use capability::{
    AttenuationError, AttenuationRequest, AuthorizationContext, AuthorizationError,
    CapabilityDraft, CapabilityRecord, CapabilityValidationError, ChannelBinding, DelegationLimits,
    Grant, InvalidGrant,
};
pub use crypto::{
    SignatureVerificationError, VerifiedSignature, sign_statement, signature_signing_message,
    verify_signature,
};
pub use format::{CanonicalCborError, DecodeLimits, descriptor_for_bytes, validate_canonical_cbor};
pub use identity::{
    AttachmentId, AttachmentSlotId, AuditId, CacheDomainId, CapabilityId, ExecutionId, ExportId,
    GrantId, IncarnationId, IssuerId, LeaseId, NetworkEndpointId, NodeId, OperationId, PrincipalId,
    ProjectId, ResourceId, RestoreScopeId, RevocationScopeId, SandboxId, SecretId, ServiceId,
    SnapshotId, TrustScopeId, ViewId,
};
pub use ownership_lease::{
    BrokerAdmissionIntersection, CLOCK_PAIR_TOLERANCE_NANOSECONDS,
    DurableHistoricalWallClockInstant, HistoricalOwnershipLeaseExpectation, InvalidOwnershipLease,
    LEASE_SAFETY_MARGIN_SECONDS, LeaseAssignment, LeaseFenceOutcome, LocalLeaseRecord,
    LocalLeaseRecordCodecError, NonAuthorizingHistoricalOwnershipLease, OwnershipLease,
    OwnershipLeaseExpectation, OwnershipLeaseTrustAnchor, OwnershipLeaseVerificationError,
    PendingLocalLeaseRecord, RawClockProvenance, RawPairedClockSample, VerifiedOwnershipLease,
    authenticate_historical_ownership_lease, decode_local_lease_record, encode_local_lease_record,
    intersect_broker_admission, prepare_local_lease_record, verify_ownership_lease,
    verify_ownership_transaction_receipt_signature,
};
pub use registry::{
    DescriptorRole, PortableMediaType, ProtocolId, ProtocolVersion, RegistryError,
    negotiate_protocol, validate_descriptor_role, validate_required_features,
    validate_signature_subject,
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
