//! Concrete storage capabilities accepted by local campaign composition.
//!
//! Operator-facing clients configure these types through the packaged daemon
//! boundary. Keeping the vocabulary here prevents the thin CLI from acquiring
//! an independent lower-layer store dependency or a second composition path.

pub use crucible_store::content_store::{
    BackendCapabilities, ContentId, DEFAULT_STORE_GRAPH_VERIFY_LOGICAL_BYTES, DirectoryBlobBackend,
    DirectoryRefBackend, DurabilityRequirement, ImmutableBlobBackend, ObjectKind, PackedRepackPlan,
    PackedStorageAccounting, RefInventorySummary, RefName, RefStoreAdmin, S3RefBackend,
    SensitivityClass, StoreEncryptionKey, StoreEncryptionKeyId, StoreError, StoreGraph,
    StoreGraphAdmin, StoreGraphConfig, StoreGraphConfigurationId, StoreGraphKeyring,
    StoreGraphNamespaceAuthorizers, StoreGraphObjectProfilers, StoreGraphPackedRepackAdmin,
    StoreGraphPhysicalQuotaBinders, StoreGraphS3Clients, StoreGraphVerificationLimits,
    StoreNamespaceAuthorizer, StoreNamespaceId, StoreNamespaceOperation, StoreNodeId,
    StoreNodeKind, StoreNodeSpec, StoreObjectProfilePolicyId, StorePhysicalQuotaPolicyId,
    StorePhysicalRepairDisposition, StorePhysicalRepairReceipt, StoreS3EndpointId,
    StoreS3RefCapability, StoreTierPolicy,
};
pub use crucible_store_s3::{AwsSdkS3Client, AwsSdkS3ClientConfig, AwsSdkS3StrongCasClient};
