//! Defines the portable model shared by AOS sandbox components.
//!
//! This crate owns logical identities, fencing generations, policy math,
//! lifecycle state machines, and portable object schemas. It deliberately has
//! no dependency on Linux system calls, D-Bus, storage commands, or a runtime
//! backend. Privileged services consume validated values from this crate but
//! do not parse public requests themselves.
//!
//! The [`identity`] module defines opaque 128-bit identifiers. The [`version`]
//! module defines monotonic counters used to reject stale work. The
//! [`model::execution`] module defines exact command, resource, I/O, and
//! observation semantics, while [`format`] owns their canonical versioned CBOR
//! encodings and digest commitments. Execution access is route-dependent: a
//! live OpenSSH route carries a validated holder key, while a detached capture
//! route carries no holder key. The [`runtime_backend`] module defines dormant
//! backend-neutral typestates plus durable execution admission, effect, and
//! recovery contracts without selecting or activating an implementation.

pub mod assignment;
pub mod broker_authorization;
pub mod capability;
pub mod crypto;
pub mod format;
pub mod guardian_binding;
pub mod identity;
pub mod model;
pub mod operator_recovery_effect;
pub mod ownership_lease;
pub mod public_attach_grant;
pub mod publisher;
pub mod registry;
pub mod resources;
pub mod runtime_backend;
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
pub use format::{
    CanonicalCborError, DecodeLimits, ObjectDescriptorVerificationError, ObjectDescriptorVerifier,
    StreamingDirectory, decode_attachment_intent_v1, decode_execution_observation_v1,
    decode_execution_spec_v1, decode_sandbox_spec, decode_view, decode_view_source,
    descriptor_for_bytes, encode_attachment_intent_v1, encode_execution_observation_v1,
    encode_execution_spec_v1, encode_sandbox_spec, encode_view, encode_view_source,
    execution_spec_digest_v1, hardlink_group_digest, resource_profile_digest_v1,
    sandbox_spec_media_type, validate_canonical_cbor,
};
pub use guardian_binding::{GuardianPlanBinding, InvalidGuardianPlanBinding};
pub use identity::{
    AttachmentId, AttachmentSlotId, AuditId, CacheDomainId, CapabilityId, ExecutionId, ExportId,
    GrantId, IncarnationId, IssuerId, LeaseId, NetworkEndpointId, NodeId, OperationId, PrincipalId,
    ProjectId, PublicationReservationId, PublisherInstanceId, ResourceId, RestoreScopeId,
    RevocationScopeId, SandboxId, SecretId, ServiceId, SnapshotId, TrustScopeId, ViewId,
};
pub use model::execution::{
    CapturedStreamV1, ExecutionAccessRouteV1, ExecutionArgumentEnvelopeV1,
    ExecutionCapturedOutputV1, ExecutionCapturedStreamKindV1, ExecutionCommandV1,
    ExecutionCredentialsV1, ExecutionDisconnectPolicyV1, ExecutionEndpointCapabilityV1,
    ExecutionEnvironmentEntry, ExecutionFailureReasonV1, ExecutionIoV1,
    ExecutionObservationAdvanceError, ExecutionObservationPhaseV1, ExecutionObservationV1,
    ExecutionOpenSshRouteV1, ExecutionOutputByteAdmissionV1, ExecutionOutputModeV1,
    ExecutionPublicKeyAlgorithmV1, ExecutionPublicKeyV1, ExecutionResourceAdmissionV1,
    ExecutionResourceRequestV1, ExecutionResourceRequestValueV1, ExecutionResourceSublimitV1,
    ExecutionResourceSublimitValueV1, ExecutionRuntimeArgumentLimitV1, ExecutionSignalV1,
    ExecutionSpecV1, ExecutionTargetV1, ExecutionTerminalModeV1, ExecutionTerminalResultV1,
    ExecutionTimeoutV1, InvalidExecutionSpec, MAX_EXECUTION_ARGUMENT_BYTES,
    MAX_EXECUTION_ARGUMENT_STRING_BYTES, MAX_EXECUTION_ARGUMENTS,
    MAX_EXECUTION_BASE_ENVIRONMENT_BYTES, MAX_EXECUTION_BASE_ENVIRONMENT_CBOR_ITEMS,
    MAX_EXECUTION_CAPTURED_STREAMS, MAX_EXECUTION_ENDPOINT_CAPABILITIES,
    MAX_EXECUTION_ENVIRONMENT_BYTES, MAX_EXECUTION_ENVIRONMENT_ENTRIES,
    MAX_EXECUTION_ENVIRONMENT_NAME_BYTES, MAX_EXECUTION_ENVIRONMENT_VALUE_BYTES,
    MAX_EXECUTION_RESOURCE_SETTINGS, MAX_EXECUTION_STRING_BYTES,
    MAX_EXECUTION_SUPPLEMENTARY_GROUPS, PayloadBootId, UnrepresentableLegacyExecutionObservation,
};
pub use model::{KeyUsage, SignaturePurpose};
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
pub use publisher::{
    InvalidPublisherAdmissionRequest, InvalidPublisherDomainPlan, PublisherAdmissionClaimV1,
    PublisherAdmissionRequestDraftV1, PublisherAdmissionRequestV1, PublisherAuthorityBindings,
    PublisherChallengeV1, PublisherDomainPlan, PublisherDomainPlanDraft, PublisherPlanExpectation,
    PublisherPlanTrustAnchor, PublisherPlanVerificationError, PublisherRequest,
    PublisherRequestCommitment, PublisherTarget, VerifiedPublisherDomainPlan,
    verify_publisher_domain_plan,
};
pub use registry::{
    BROKER_SESSION_AUTHENTICATION_FEATURE_NAMESPACE, DescriptorRole,
    HOST_EXECUTION_SPEC_DESCRIPTOR_FEATURE_NAMESPACE, PortableMediaType, ProtocolId,
    ProtocolVersion, RegistryError, negotiate_protocol, supported_protocol_version,
    validate_descriptor_role, validate_required_features, validate_signature_subject,
};
pub use resources::{
    AccountingError, AncestryAdmissionError, ReservationClass, ResourceAccount, ResourceBudget,
    ResourceCeilings, ResourceDimension, ResourceLimit, ResourceVector,
};
pub use runtime_backend::ExecutionAdmissionDraftV1;
pub use selector::{
    FeatureRef, InvalidPathName, MediaType, ObjectDescriptor, ObjectDigest, Operation,
    OperationSet, PathName, RelativePath, ResourceKind, Selector,
};
pub use version::{
    AssignmentEpoch, DesiredGeneration, NamespaceGeneration, ObservationSequence, Revision,
};
