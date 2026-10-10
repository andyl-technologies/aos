//! Concrete storage capabilities accepted by local campaign composition.
//!
//! Operator-facing clients configure these types through the packaged daemon
//! boundary. Keeping the vocabulary here prevents the thin CLI from acquiring
//! an independent lower-layer store dependency or a second composition path.

mod supervision;
pub use supervision::CampaignArchiveHostOperation;

/// Typed cancellation and integrity failure at an archive storage boundary.
pub type CampaignArchiveBoundaryError = crucible_cas::ram::RamStoreError;

/// Explicit physical and logical admission bounds for an archive RAM closure.
pub type CampaignArchiveRamLimits = crucible_cas::ram::RamStoreLimits;

pub use crucible_cas::content_store::{
    BackendCapabilities, ContentId, DirectoryBlobBackend, DirectoryRefBackend,
    DurabilityRequirement, ImmutableBlobBackend, MAX_STORE_GRAPH_VERIFY_LOGICAL_BYTES,
    MAX_STORE_GRAPH_VERIFY_PLACEMENTS, ObjectKind, PackedRepackPlan, PackedStorageAccounting,
    RefInventorySummary, RefName, RefStoreAdmin, S3RefBackend, SensitivityClass, SqliteProcessHeap,
    StoreEncryptionKey, StoreEncryptionKeyId, StoreError, StoreGraph, StoreGraphAdmin,
    StoreGraphConfig, StoreGraphConfigurationId, StoreGraphKeyring, StoreGraphNamespaceAuthorizers,
    StoreGraphObjectProfilers, StoreGraphOriginalResources, StoreGraphPackedRepackAdmin,
    StoreGraphPhysicalQuotaBinders, StoreGraphS3Clients, StoreGraphVerificationLimits,
    StoreGraphVerificationLimitsError, StoreNamespaceAuthorizer, StoreNamespaceId,
    StoreNamespaceOperation, StoreNodeId, StoreNodeKind, StoreNodeSpec, StoreObjectProfilePolicyId,
    StorePhysicalQuotaBinder, StorePhysicalQuotaGuard, StorePhysicalQuotaPolicyId,
    StorePhysicalRepairDisposition, StorePhysicalRepairReceipt, StoreS3EndpointId,
    StoreS3RefCapability, StoreTierPolicy,
};
pub use crucible_s3_store::{AwsSdkS3Client, AwsSdkS3ClientConfig, AwsSdkS3StrongCasClient};
