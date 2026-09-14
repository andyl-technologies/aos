//! Checked controller-query projections and public redaction boundaries.
//!
//! [`resource`] validates established public protobuf resources without
//! creating a second serialized schema. [`redaction`] keeps protected
//! operator observations in a distinct, non-serializable projection, while
//! [`model`] and [`event`] bind opaque response state to exact query semantics.

pub mod event;
mod client_state_sealed {
    pub trait Sealed {}
}
pub mod model;
pub mod observation;
pub mod operator;
pub mod portable;
pub mod portable_resource;
pub mod redaction;
mod registry;
pub mod resource;

pub use event::{
    BoundWatchCursorV1, BoundWatchWatermarkV1, CheckedWatchEventV1, InvalidWatchEvent,
    MAXIMUM_EVENT_EXTENSIONS, MAXIMUM_EVENT_EXTENSION_BYTES,
};
pub use model::{
    AuthorizationRevisionDigestV1, ClientStateItem, InvalidQueryModel, NormalizedQueryDigestV1,
    ObservationSchemaDigestV1, QueryBindingV1, QueryFilterDigestV1, QueryPrincipalDigestV1,
    QuerySortDigestV1, QueryVisibilityDigestV1, MAXIMUM_OPAQUE_RESPONSE_BYTES,
    MAXIMUM_PUBLIC_RESOURCE_BYTES,
};
pub use observation::{
    ActiveExecutionSetV1, AdditiveControllerObservationV1, AttachmentGenerationSetV1,
    AttachmentGenerationStatusV1, AttachmentHealthV1, AuditEventCursorV1, CacheDomainIdentityV1,
    CacheStatusV1, CheckedConditionObservationV1, CheckedOperationObservationV1,
    CheckedSandboxObservationV1, ConditionFreshnessV1, ConditionReasonV1,
    DisclosureDomainIdentityV1, DisclosureStatusV1, GuardianEvidenceV1, GuardianStatusV1,
    InvalidObservationMetadata, LogicalUsageStatusV1, OwnershipEvidenceV1, OwnershipLeaseStatusV1,
    OwnershipTransactionStateV1, OwnershipTransactionStatusV1, PublicTimestampV1,
    RealizedRootStatusV1, MAXIMUM_AUDIT_CURSOR_BYTES, MAXIMUM_PINNED_REFERENCES,
    MAXIMUM_STATUS_REFERENCES, PUBLIC_PROTO_INTEGRATION_REQUIRED,
};
pub use operator::{
    InvalidOperatorDiagnostics, OperatorDiagnosticKindV1, OperatorDiagnosticV1,
    OperatorDiagnosticValueV1, OperatorDiagnosticsV1, OperatorLocalIdentifierV1,
    MAXIMUM_OPERATOR_DIAGNOSTICS, MAXIMUM_OPERATOR_LOCAL_NAME_BYTES,
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
    project_operation_for_operator, project_sandbox_for_operator, redact_operation_for_public,
    redact_sandbox_for_public, ControllerOperationQueryV1, ControllerSandboxQueryV1,
    InvalidControllerProjection, OperatorOperationProjectionV1, OperatorSandboxProjectionV1,
    PlacementAuthorityStateV1,
};
pub use resource::{
    operation_phase_can_follow, CheckedConditionV1, CheckedOperationPhaseV1,
    CheckedOperationResourceV1, CheckedPlacementV1, CheckedResourceReferenceV1,
    CheckedRetryClassV1, CheckedSandboxResourceV1, InvalidPublicResource, PublicConditionCodeV1,
    PublicMilestoneV1, PublicOperationMethodV1, PublicResourceTypeV1, MAXIMUM_CONDITION_FEATURES,
    MAXIMUM_OPERATION_RESULTS, MAXIMUM_RESOURCE_CONDITIONS, MAXIMUM_SAFE_MESSAGE_BYTES,
};
