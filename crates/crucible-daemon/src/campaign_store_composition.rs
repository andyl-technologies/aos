//! Concrete storage capabilities accepted by local campaign composition.
//!
//! Operator-facing clients configure these types through the packaged daemon
//! boundary. Keeping the vocabulary here prevents the thin CLI from acquiring
//! an independent lower-layer store dependency or a second composition path.

pub use crucible_cas::content_store::{
    BackendCapabilities, BlobInventoryRecord, ContentId, DirectoryRefBackend,
    DurabilityRequirement, ImmutableBlobBackend, ObjectKind, S3RefBackend, StoreEncryptionKey,
    StoreEncryptionKeyId, StoreError, StoreGraph, StoreGraphAdmin, StoreGraphConfig,
    StoreGraphKeyring, StoreGraphNamespaceAuthorizers, StoreGraphObjectProfilers,
    StoreGraphPhysicalQuotaBinders, StoreGraphS3Clients, StoreNamespaceAuthorizer,
    StoreNamespaceId, StoreNamespaceOperation, StoreNodeId, StoreNodeKind, StoreNodeSpec,
    StoreObjectProfilePolicyId, StorePhysicalQuotaPolicyId, StoreS3EndpointId,
    StoreS3RefCapability,
};
pub use crucible_s3_store::{AwsSdkS3Client, AwsSdkS3ClientConfig, AwsSdkS3StrongCasClient};
