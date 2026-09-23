//! Portable authority and content data models.
//!
//! These modules define validated semantic values for the portable v1 CDDL.
//! They intentionally do not define the canonical CBOR codec: [`crate`] users
//! cannot mistake a convenient Serde representation for the signed wire form.

pub mod assignment;
pub mod domain;
pub mod execution;
pub mod policy;
pub mod snapshot;
pub mod spec;
pub mod tree;
pub mod trust;
pub mod view;

// Models share the set-ordering rule while retaining their own error types and bounds.
fn strictly_increasing<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

pub use assignment::{
    AssignmentManifestV1, InvalidAssignmentManifest, MAX_ASSIGNMENT_REQUIRED_FEATURES,
    MAX_ASSIGNMENT_SOURCE_COMMITMENTS,
};
pub use domain::{
    AttachmentConsistency, AttachmentIntent, AttachmentLease, InvalidDomainModel,
    MAX_ANCESTRY_DEPTH, MountAttributes, PlacementAssignment, PlacementRequest, SandboxAncestry,
};
pub use execution::{
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
pub(crate) use execution::{
    MAX_EXECUTION_BASE_ENVIRONMENT_COLLECTION_ITEMS, MAX_EXECUTION_BASE_ENVIRONMENT_FEATURES,
    MAX_EXECUTION_OUTPUT_ASSIGNMENT_BYTES,
};
pub use policy::{
    ExplanationReason, ExplanationReasonCode, InvalidPolicyModel, Optimization, OptimizationKind,
    OptimizationProfile, Policy, PolicyViewAction, RevocationMode, RevocationPolicy,
};
pub use snapshot::{
    AttachmentSnapshot, ExternalDependency, InvalidSnapshotModel, OpaqueVersion, QuiesceEvidence,
    Receipt, RetentionClaim, Snapshot, SnapshotConsistency, SourceAssignment, StorageCheckpoint,
};
pub use spec::{
    IdentityProfile, InvalidSpecModel, Limit, LimitDimension, LimitValue, NetworkKind,
    NetworkProfile, ResourceProfile, SandboxSpec, UnmappableIdentityPolicy,
};
pub use tree::{
    Acl, AclEntry, ContentLayout, Delta, Directory, DirectoryEntry, Extent, FileNode,
    FilesystemMetadata, InvalidTreeModel, Node, SparseContent, SymlinkNode, Tree, Xattr,
};
pub use trust::{
    InvalidTrustModel, KeyReference, KeyUsage, Signature, SignatureBytes, SignaturePurpose,
    SignatureStatement, StableKeyId, TrustPolicy,
};
pub use view::{
    CacheDomain, CacheDomainKind, Environment, EnvironmentEntry, InvalidViewModel,
    PresentationAction, View, ViewConsistency, ViewMutation, ViewSource,
};
pub(crate) use view::{MAX_ENVIRONMENT_NAME_BYTES, MAX_ENVIRONMENT_VALUE_BYTES};
