//! Pure checked public sandbox models shared by clients and the Controller.
//!
//! Resource and observation wrappers retain the established protobuf schema;
//! [`registry`] validates closed semantic features. [`model`], [`event`], and
//! [`client_state`] bind bounded pagination, wait, and watch state to exact
//! query semantics. Structural checks do not authenticate a request, adopt its
//! provenance, or grant mutation or effect authority. Terminal projection and
//! the shared error vocabulary remain in [`execution_result`] and [`grammar_error`].
//! [`proto_json`] and [`continuation`] retain checked output and bounded resume
//! data. [`attach_holder_proof`] and [`create_holder_proof`] validate holder-key
//! claims without granting admission, adoption, or effect authority.
//! [`request`] owns the sole structurally checked public request DATA and
//! untrusted client proposals under the shared [`limits`].
//! [`method`] and [`mutation`] preserve exact mutation envelopes and resolve
//! historical endpoint selectors without adopting current native authority.

pub mod attach_holder_proof;
pub mod audit_event;
pub mod continuation;
pub mod create_holder_proof;
pub mod event;
pub mod method;
pub mod model;
pub mod mutation;
pub mod observation;
pub mod portable;
pub mod portable_resource;
pub mod proto_json;
mod proto_observation;
pub mod registry;
pub mod resource;
pub mod watch;
pub mod watch_resource;
pub mod client_state;
pub mod execution_result;
pub mod grammar_error;
pub mod limits;
pub mod request;

mod client_state_sealed {
    pub trait Sealed {}
}

pub use audit_event::{
    CheckedAuditWatchEventV1, InvalidAuditWatchEvent, MAXIMUM_AUDIT_IDENTITY_BYTES,
};
pub use event::{
    BoundWatchCursorV1, BoundWatchWatermarkV1, CheckedWatchEventV1, InvalidWatchEvent,
    MAXIMUM_EVENT_EXTENSION_BYTES, MAXIMUM_EVENT_EXTENSIONS,
};
pub use model::{
    AuthorizationRevisionDigestV1, ClientStateItem, InvalidQueryModel,
    MAXIMUM_OPAQUE_RESPONSE_BYTES, MAXIMUM_PUBLIC_RESOURCE_BYTES, NormalizedQueryDigestV1,
    ObservationSchemaDigestV1, QUERY_BINDING_TRANSPORT_BYTES, QueryBindingV1, QueryFilterDigestV1,
    QueryPrincipalDigestV1, QuerySortDigestV1, QueryVisibilityDigestV1, WatchRequestCommitmentV1,
};
pub use observation::{
    ActiveExecutionSetV1, AdditiveControllerObservationV1, AttachmentGenerationSetV1,
    AttachmentGenerationStatusV1, AttachmentHealthV1, AuditEventCursorV1, CacheDomainIdentityV1,
    CacheStatusV1, CheckedConditionObservationV1, CheckedOperationObservationV1,
    CheckedSandboxObservationV1, ConditionFreshnessV1, ConditionReasonV1,
    DisclosureDomainIdentityV1, DisclosureStatusV1, GuardianEvidenceV1, GuardianStatusV1,
    InvalidObservationMetadata, LogicalUsageStatusV1, MAXIMUM_AUDIT_CURSOR_BYTES,
    MAXIMUM_PINNED_REFERENCES, MAXIMUM_STATUS_REFERENCES, OwnershipEvidenceV1,
    OwnershipLeaseStatusV1, OwnershipTransactionStateV1, OwnershipTransactionStatusV1,
    PUBLIC_PROTO_INTEGRATION_REQUIRED, PublicTimestampV1, RealizedRootStatusV1,
};
pub use portable::{
    CheckedFeatureSetV1, CheckedFilesystemViewDescriptorV1, CheckedObjectDescriptorV1,
    CheckedPolicyDescriptorV1, CheckedSandboxSpecificationV1,
};
pub use portable_resource::{
    CheckedAttachmentResourceV1, CheckedCapabilityResourceV1, CheckedExecutionResourceV1,
    CheckedFilesystemViewResourceV1, CheckedNodeCapabilitiesV1, CheckedSnapshotResourceV1,
};
pub use registry::{
    ATTACHMENT_NOEXEC_FEATURE_V1, BASE_V1_FEATURE_REGISTRY_ENTRIES, CACHE_CONSUMER_PIN_FEATURE_V1,
    EXECUTION_ATTACH_HOLDER_PROOF_FEATURE_V1, EXECUTION_CREATE_HOLDER_PROOF_FEATURE_V1,
    EXECUTION_DETACHED_CAPTURE_FEATURE_V1, EXECUTION_DETACHED_CAPTURE_STREAM_CEILINGS_FEATURE_V1,
    EXECUTION_PTY_FEATURE_V1, EXECUTION_SANDBOX_SHELL_FEATURE_V1, EXECUTION_STREAM_FEATURE_V1,
    EXECUTION_TIMEOUT_FEATURE_V1, FORCE_DELETE_FEATURE_V1, PublicPolicyReasonCodeV1,
    SNAPSHOT_PROJECT_VERSION_FENCE_FEATURE_V1, canonical_feature_fixture_v1,
    contains_semantic_features_v1, public_feature_registry_v1, semantic_feature_v1,
};
pub use resource::{
    CheckedConditionV1, CheckedOperationPhaseV1, CheckedOperationResourceV1, CheckedPlacementV1,
    CheckedResourceReferenceV1, CheckedRetryClassV1, CheckedSandboxResourceV1,
    InvalidPublicResource, MAXIMUM_CONDITION_FEATURES, MAXIMUM_OPERATION_RESULTS,
    MAXIMUM_RESOURCE_CONDITIONS, MAXIMUM_SAFE_MESSAGE_BYTES, PublicConditionCodeV1,
    PublicMilestoneV1, PublicOperationMethodV1, PublicResourceTypeV1, operation_phase_can_follow,
};
pub use watch::{
    AuthenticatedWatchReadBatchV1, AuthenticatedWatchReadRequestV1, CheckedObservationWatchInputV1,
    CheckedWatchRequestV1, MAXIMUM_AUTHENTICATED_WATCH_INPUTS, ObservationWatchAdvanceV1,
    ObservationWatchContinuationV1, ObservationWatchError, WatchSurfaceV1,
    checked_watch_request_commitment_v1,
};
pub use watch_resource::{
    CheckedWatchSnapshotResourceV1, InvalidWatchSnapshotResource, PublicWatchSnapshotResourceRefV1,
    WatchSnapshotResourceTypeV1,
};
