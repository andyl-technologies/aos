//! Checked controller-query projections and public redaction boundaries.
//!
//! [`resource`] validates established public protobuf resources without
//! creating a second serialized schema. [`redaction`] keeps protected
//! operator observations in a distinct, non-serializable projection, while
//! [`model`] and [`event`] bind opaque response state to exact query semantics.

pub mod audit_event;
pub mod event;
pub mod metrics;
mod client_state_sealed {
    pub trait Sealed {}
}
pub mod model;
pub mod observability;
pub mod observation;
pub mod operator;
pub mod portable;
pub mod portable_resource;
mod proto_observation;
pub mod redaction;
mod registry;
pub mod resource;
pub mod watch;
pub mod watch_resource;

pub use audit_event::{
    CheckedAuditWatchEventV1, InvalidAuditWatchEvent, MAXIMUM_AUDIT_IDENTITY_BYTES,
};
pub use event::{
    BoundWatchCursorV1, BoundWatchWatermarkV1, CheckedWatchEventV1, InvalidWatchEvent,
    MAXIMUM_EVENT_EXTENSION_BYTES, MAXIMUM_EVENT_EXTENSIONS,
};
pub use metrics::{
    InvalidMetricObservation, MAXIMUM_LABELS_PER_OBSERVATION, MAXIMUM_METRIC_NODES,
    MAXIMUM_METRIC_OBSERVATIONS, MAXIMUM_METRIC_PROJECTS, MetricBackendV1,
    MetricCapabilityProfileV1, MetricLabelKeyV1, MetricLabelValueV1, MetricStatusClassV1,
    MetricValueKindV1, MetricValueV1, PortableMetricBatchV1, PortableMetricObservationV1,
    SandboxMetricNameV1,
};
pub use model::{
    AuthorizationRevisionDigestV1, ClientStateItem, InvalidQueryModel,
    MAXIMUM_OPAQUE_RESPONSE_BYTES, MAXIMUM_PUBLIC_RESOURCE_BYTES, NormalizedQueryDigestV1,
    ObservationSchemaDigestV1, QUERY_BINDING_TRANSPORT_BYTES, QueryBindingV1, QueryFilterDigestV1,
    QueryPrincipalDigestV1, QuerySortDigestV1, QueryVisibilityDigestV1, WatchRequestCommitmentV1,
};
pub use observability::*;
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
pub use operator::{
    InvalidOperatorDiagnostics, MAXIMUM_OPERATOR_DIAGNOSTICS, MAXIMUM_OPERATOR_LOCAL_NAME_BYTES,
    OperatorDiagnosticKindV1, OperatorDiagnosticV1, OperatorDiagnosticValueV1,
    OperatorDiagnosticsV1, OperatorLocalIdentifierV1,
};
pub use portable::{
    CheckedFeatureSetV1, CheckedFilesystemViewDescriptorV1, CheckedObjectDescriptorV1,
    CheckedPolicyDescriptorV1, CheckedSandboxSpecificationV1,
};
pub use portable_resource::{
    CheckedAttachmentResourceV1, CheckedCapabilityResourceV1, CheckedExecutionResourceV1,
    CheckedFilesystemViewResourceV1, CheckedNodeCapabilitiesV1, CheckedSnapshotResourceV1,
};
pub use redaction::{
    ControllerOperationQueryV1, ControllerSandboxQueryV1, InvalidControllerProjection,
    OperatorOperationProjectionV1, OperatorSandboxProjectionV1, PlacementAuthorityStateV1,
    project_operation_for_operator, project_sandbox_for_operator, redact_operation_for_public,
    redact_sandbox_for_public,
};
pub use registry::{
    ATTACHMENT_NOEXEC_FEATURE_V1, BASE_V1_FEATURE_REGISTRY_ENTRIES,
    EXECUTION_DETACHED_CAPTURE_FEATURE_V1, EXECUTION_PTY_FEATURE_V1,
    EXECUTION_SANDBOX_SHELL_FEATURE_V1, EXECUTION_STREAM_FEATURE_V1, EXECUTION_TIMEOUT_FEATURE_V1,
    FORCE_DELETE_FEATURE_V1, PublicPolicyReasonCodeV1, SNAPSHOT_PROJECT_VERSION_FENCE_FEATURE_V1,
    canonical_feature_fixture_v1, contains_semantic_features_v1, public_feature_registry_v1,
    semantic_feature_v1,
};
pub(crate) use registry::{
    base_feature_registry_entry_v1, feature_conformance_digest_v1,
    public_feature_registry_digest_v1,
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
