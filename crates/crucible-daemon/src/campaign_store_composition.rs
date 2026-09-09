//! Concrete storage capabilities accepted by local campaign composition.
//!
//! Operator-facing clients configure these types through the packaged daemon
//! boundary. Keeping the vocabulary here prevents the thin CLI from acquiring
//! an independent lower-layer store dependency or a second composition path.

pub use crucible_cas::content_store::{
    BackendCapabilities, ContentId, DirectoryBlobBackend, DirectoryRefBackend,
    DurabilityRequirement, ImmutableBlobBackend, MAX_STORE_GRAPH_VERIFY_LOGICAL_BYTES,
    MAX_STORE_GRAPH_VERIFY_PLACEMENTS, ObjectKind, RefName, S3RefBackend, SensitivityClass,
    StoreEncryptionKey, StoreEncryptionKeyId, StoreError, StoreGraph, StoreGraphAdmin,
    StoreGraphConfig, StoreGraphKeyring, StoreGraphNamespaceAuthorizers, StoreGraphObjectProfilers,
    StoreGraphPhysicalQuotaBinders, StoreGraphS3Clients, StoreGraphVerificationLimits,
    StoreGraphVerificationLimitsError, StoreNamespaceAuthorizer, StoreNamespaceId,
    StoreNamespaceOperation, StoreNodeId, StoreNodeKind, StoreNodeSpec, StoreObjectProfilePolicyId,
    StorePhysicalQuotaPolicyId, StoreS3EndpointId, StoreS3RefCapability,
};
pub use crucible_s3_store::{AwsSdkS3Client, AwsSdkS3ClientConfig, AwsSdkS3StrongCasClient};
