//! Read-only access to validated SourceProvider model fields.
//!
//! Construction and decoding remain centralized in `model` and `codec`; these
//! accessors let later journal and backend implementations compare every
//! validated field without exposing mutable wire state.

use aos_sandbox_core::ObjectDigest;

use crate::crypto::SourceProviderSigningKeyV1;
use crate::model::{
    AcquireSourceRequestV1, InventoryLeaseStateV1, InventorySourceRequestV1,
    ReleaseSourceRequestV1, SourceExportLeaseV1, SourceProviderInventoryEntryV1,
    SourceProviderInventoryV1, SourceProviderReceiptV1, SourceReleaseReceiptV1,
};
use crate::proof::{
    BestEffortReplicaProofV1, ImmutablePublisherTreeProofV1, LocalLiveExportProofV1,
    ZfsHeldSnapshotProofV1,
};

impl SourceProviderSigningKeyV1 {
    /// Returns the stable key ID.
    #[must_use]
    pub const fn key_id(&self) -> [u8; 16] {
        self.key_id
    }

    /// Returns the key generation.
    #[must_use]
    pub const fn key_generation(&self) -> u64 {
        self.key_generation
    }

    /// Returns SHA-256 over the exact Ed25519 public key.
    #[must_use]
    pub const fn public_key_digest(&self) -> ObjectDigest {
        self.public_key_digest
    }
}

impl AcquireSourceRequestV1 {
    /// Returns the exact deadline-free canonical `AOSMSEM1` bytes.
    #[must_use]
    pub fn prospective_apply_template(&self) -> &[u8] {
        &self.prospective_apply_template
    }

    /// Returns the target node ID.
    #[must_use]
    pub const fn node_id(&self) -> [u8; 16] {
        self.node_id
    }

    /// Returns the target kernel boot ID.
    #[must_use]
    pub const fn boot_id(&self) -> [u8; 16] {
        self.boot_id
    }

    /// Returns the stable Root Mount holder authority ID.
    #[must_use]
    pub const fn holder_authority_id(&self) -> [u8; 16] {
        self.holder_authority_id
    }

    /// Returns the Root Mount holder generation.
    #[must_use]
    pub const fn holder_generation(&self) -> u64 {
        self.holder_generation
    }

    /// Returns the exact Root Mount authority-state digest.
    #[must_use]
    pub const fn holder_authority_digest(&self) -> ObjectDigest {
        self.holder_authority_digest
    }

    /// Returns the exclusive request deadline in Unix seconds.
    #[must_use]
    pub const fn deadline_seconds(&self) -> i64 {
        self.deadline_seconds
    }

    /// Returns the maximum requested provider lease duration.
    #[must_use]
    pub const fn requested_lease_seconds(&self) -> u64 {
        self.requested_lease_seconds
    }

    /// Returns the exact revocation-state commitment.
    #[must_use]
    pub const fn revocation_digest(&self) -> ObjectDigest {
        self.revocation_digest
    }

    /// Reports whether recursive traversal was requested.
    #[must_use]
    pub const fn recursive(&self) -> bool {
        self.recursive
    }

    /// Returns the maximum requested source submount count.
    #[must_use]
    pub const fn requested_maximum_submounts(&self) -> u32 {
        self.requested_maximum_submounts
    }

    /// Reports whether the request requires a kernel-coupled provider grant.
    #[must_use]
    pub const fn kernel_coupled(&self) -> bool {
        self.kernel_coupled
    }
}

impl SourceExportLeaseV1 {
    /// Returns the provider request ID that created this lease.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the stable Root Mount holder authority ID.
    #[must_use]
    pub const fn holder_authority_id(&self) -> [u8; 16] {
        self.holder_authority_id
    }

    /// Returns the Root Mount holder generation.
    #[must_use]
    pub const fn holder_generation(&self) -> u64 {
        self.holder_generation
    }

    /// Returns the exact Root Mount authority-state digest.
    #[must_use]
    pub const fn holder_authority_digest(&self) -> ObjectDigest {
        self.holder_authority_digest
    }

    /// Returns the committed logical binding digest.
    #[must_use]
    pub const fn binding_digest(&self) -> ObjectDigest {
        self.binding_digest
    }

    /// Returns the claimed inclusive lease issue time in Unix seconds.
    #[must_use]
    pub const fn issued_seconds(&self) -> i64 {
        self.issued_seconds
    }

    /// Returns the claimed exclusive lease expiry in Unix seconds.
    #[must_use]
    pub const fn expires_seconds(&self) -> i64 {
        self.expires_seconds
    }

    /// Returns the revocation-state commitment.
    #[must_use]
    pub const fn revocation_digest(&self) -> ObjectDigest {
        self.revocation_digest
    }
}

impl SourceProviderReceiptV1 {
    /// Returns the provider request ID.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the digest of the exact acquisition query.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.request_digest
    }

    /// Returns the Mount-minted acquisition ID.
    #[must_use]
    pub const fn acquisition_id(&self) -> ObjectDigest {
        self.acquisition_id
    }

    /// Returns the kernel boot ID claimed by the provider receipt.
    #[must_use]
    pub const fn kernel_boot_id(&self) -> [u8; 16] {
        self.kernel_boot_id
    }

    /// Returns the device identity claimed by the provider receipt.
    #[must_use]
    pub const fn device(&self) -> u64 {
        self.device
    }

    /// Returns the inode identity claimed by the provider receipt.
    #[must_use]
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    /// Returns the unique mount ID claimed by the provider receipt.
    #[must_use]
    pub const fn unique_mount_id(&self) -> u64 {
        self.unique_mount_id
    }

    /// Returns the provider's digest of its complete proof claim.
    #[must_use]
    pub const fn observed_proof_digest(&self) -> ObjectDigest {
        self.observed_proof_digest
    }
}

impl ReleaseSourceRequestV1 {
    /// Returns the claimed hello-transcript binding.
    #[must_use]
    pub const fn session_binding(&self) -> ObjectDigest {
        self.session_binding
    }

    /// Returns the client-to-provider sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the idempotency request ID.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the Mount acquisition being released.
    #[must_use]
    pub const fn acquisition_id(&self) -> ObjectDigest {
        self.acquisition_id
    }

    /// Returns the stable Root Mount holder authority ID.
    #[must_use]
    pub const fn holder_authority_id(&self) -> [u8; 16] {
        self.holder_authority_id
    }

    /// Returns the Root Mount holder generation.
    #[must_use]
    pub const fn holder_generation(&self) -> u64 {
        self.holder_generation
    }

    /// Returns the exact Root Mount authority-state digest.
    #[must_use]
    pub const fn holder_authority_digest(&self) -> ObjectDigest {
        self.holder_authority_digest
    }

    /// Returns the exact provider lease ID.
    #[must_use]
    pub const fn lease_id(&self) -> [u8; 16] {
        self.lease_id
    }

    /// Returns the claimed digest of the exact signed provider lease.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns the exclusive request deadline in Unix seconds.
    #[must_use]
    pub const fn deadline_seconds(&self) -> i64 {
        self.deadline_seconds
    }
}

impl InventorySourceRequestV1 {
    /// Returns the claimed hello-transcript binding.
    #[must_use]
    pub const fn session_binding(&self) -> ObjectDigest {
        self.session_binding
    }

    /// Returns the client-to-provider sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the idempotency request ID.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the stable Root Mount holder authority ID.
    #[must_use]
    pub const fn holder_authority_id(&self) -> [u8; 16] {
        self.holder_authority_id
    }

    /// Returns the Root Mount holder generation.
    #[must_use]
    pub const fn holder_generation(&self) -> u64 {
        self.holder_generation
    }

    /// Returns the exact Root Mount authority-state digest.
    #[must_use]
    pub const fn holder_authority_digest(&self) -> ObjectDigest {
        self.holder_authority_digest
    }

    /// Returns the caller's exact prior inventory commitment, when present.
    #[must_use]
    pub const fn known_inventory_digest(&self) -> Option<ObjectDigest> {
        self.known_inventory_digest
    }

    /// Returns the exclusive request deadline in Unix seconds.
    #[must_use]
    pub const fn deadline_seconds(&self) -> i64 {
        self.deadline_seconds
    }
}

impl SourceReleaseReceiptV1 {
    /// Returns the provider request ID.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the digest of the exact release query.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.request_digest
    }

    /// Returns the released lease ID.
    #[must_use]
    pub const fn lease_id(&self) -> [u8; 16] {
        self.lease_id
    }

    /// Returns the claimed digest of the released signed lease.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns the stable provider authority.
    #[must_use]
    pub const fn provider(&self) -> &crate::model::ProviderAuthorityV1 {
        &self.provider
    }

    /// Returns the process instance named as this receipt's issuer.
    #[must_use]
    pub const fn provider_process_instance(&self) -> [u8; 16] {
        self.provider_process_instance
    }

    /// Returns the monotonic release generation.
    #[must_use]
    pub const fn release_generation(&self) -> u64 {
        self.release_generation
    }

    /// Returns the release time in Unix seconds.
    #[must_use]
    pub const fn released_seconds(&self) -> i64 {
        self.released_seconds
    }
}

impl SourceProviderInventoryEntryV1 {
    /// Returns the exact provider lease ID.
    #[must_use]
    pub const fn lease_id(&self) -> [u8; 16] {
        self.lease_id
    }

    /// Returns the claimed digest of the exact signed lease.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns the Mount acquisition ID.
    #[must_use]
    pub const fn acquisition_id(&self) -> ObjectDigest {
        self.acquisition_id
    }

    /// Returns the provider's claimed durable lease state.
    #[must_use]
    pub const fn state(&self) -> InventoryLeaseStateV1 {
        self.state
    }

    /// Returns the complete provider resource selection.
    #[must_use]
    pub const fn resource(&self) -> &crate::model::SourceResourceV1 {
        &self.resource
    }

    /// Returns the closed backend proof class code.
    #[must_use]
    pub const fn proof_class(&self) -> u8 {
        self.proof_class
    }

    /// Returns the exact complete provider-proof digest.
    #[must_use]
    pub const fn proof_digest(&self) -> ObjectDigest {
        self.proof_digest
    }

    /// Returns the exact provider resource/proof commitment.
    #[must_use]
    pub const fn resource_commitment(&self) -> ObjectDigest {
        self.resource_commitment
    }
}

impl SourceProviderInventoryV1 {
    /// Returns the provider request ID.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the exact inventory-query digest.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.request_digest
    }

    /// Returns the stable Root Mount holder authority ID.
    #[must_use]
    pub const fn holder_authority_id(&self) -> [u8; 16] {
        self.holder_authority_id
    }

    /// Returns the Root Mount holder generation.
    #[must_use]
    pub const fn holder_generation(&self) -> u64 {
        self.holder_generation
    }

    /// Returns the exact Root Mount authority-state digest.
    #[must_use]
    pub const fn holder_authority_digest(&self) -> ObjectDigest {
        self.holder_authority_digest
    }

    /// Returns the stable provider authority.
    #[must_use]
    pub const fn provider(&self) -> &crate::model::ProviderAuthorityV1 {
        &self.provider
    }

    /// Returns the process instance named as this inventory's issuer.
    #[must_use]
    pub const fn provider_process_instance(&self) -> [u8; 16] {
        self.provider_process_instance
    }

    /// Returns the provider catalog generation.
    #[must_use]
    pub const fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }

    /// Returns the provider catalog digest.
    #[must_use]
    pub const fn catalog_digest(&self) -> ObjectDigest {
        self.catalog_digest
    }

    /// Returns the monotonic inventory snapshot generation.
    #[must_use]
    pub const fn inventory_generation(&self) -> u64 {
        self.inventory_generation
    }
}

macro_rules! proof_accessors {
    ($type:ty, $(($name:ident, $return:ty, $field:ident, $doc:literal)),+ $(,)?) => {
        impl $type {
            $(
                #[doc = $doc]
                #[must_use]
                pub const fn $name(&self) -> $return { self.$field }
            )+
        }
    };
}

proof_accessors!(
    ZfsHeldSnapshotProofV1,
    (
        storage_handle,
        [u8; 32],
        storage_handle,
        "Returns the claimed Storage handle."
    ),
    (
        storage_version,
        u64,
        storage_version,
        "Returns the claimed Storage format version."
    ),
    (pool_guid, u64, pool_guid, "Returns the ZFS pool GUID."),
    (
        dataset_guid,
        u64,
        dataset_guid,
        "Returns the ZFS dataset GUID."
    ),
    (
        snapshot_guid,
        u64,
        snapshot_guid,
        "Returns the ZFS snapshot GUID."
    ),
    (hold_id, [u8; 16], hold_id, "Returns the stable hold ID."),
    (
        hold_generation,
        u64,
        hold_generation,
        "Returns the hold generation."
    ),
    (
        active_hold_digest,
        ObjectDigest,
        active_hold_digest,
        "Returns the active-hold state digest."
    ),
    (
        root_policy_digest,
        ObjectDigest,
        root_policy_digest,
        "Returns the source-root policy digest."
    ),
    (
        read_only_content_digest,
        ObjectDigest,
        read_only_content_digest,
        "Returns the read-only content digest."
    ),
);
proof_accessors!(
    LocalLiveExportProofV1,
    (
        source_assignment_digest,
        ObjectDigest,
        source_assignment_digest,
        "Returns the source assignment digest."
    ),
    (
        owner_sandbox,
        [u8; 16],
        owner_sandbox,
        "Returns the source owner sandbox ID."
    ),
    (
        source_incarnation,
        [u8; 16],
        source_incarnation,
        "Returns the source incarnation ID."
    ),
    (
        export_id,
        [u8; 16],
        export_id,
        "Returns the claimed export ID."
    ),
    (
        export_generation,
        u64,
        export_generation,
        "Returns the export generation."
    ),
    (
        export_revocation_digest,
        ObjectDigest,
        export_revocation_digest,
        "Returns the export revocation-state digest."
    ),
    (
        export_lease_digest,
        ObjectDigest,
        export_lease_digest,
        "Returns the source export-lease digest."
    ),
    (
        consumer_authority_id,
        [u8; 16],
        consumer_authority_id,
        "Returns the export consumer authority ID."
    ),
    (
        consumer_generation,
        u64,
        consumer_generation,
        "Returns the export consumer generation."
    ),
    (
        kernel_grant_digest,
        ObjectDigest,
        kernel_grant_digest,
        "Returns the kernel-coupled access-grant digest."
    ),
    (
        workspace_id,
        [u8; 32],
        workspace_id,
        "Returns the claimed workspace ID."
    ),
    (
        workspace_digest,
        ObjectDigest,
        workspace_digest,
        "Returns the exact workspace-state digest."
    ),
);
proof_accessors!(
    ImmutablePublisherTreeProofV1,
    (
        tree_digest,
        ObjectDigest,
        tree_digest,
        "Returns the immutable tree digest."
    ),
    (
        view_digest,
        ObjectDigest,
        view_digest,
        "Returns the immutable view digest."
    ),
    (
        publication_generation,
        u64,
        publication_generation,
        "Returns the publisher generation."
    ),
    (
        publication_receipt_digest,
        ObjectDigest,
        publication_receipt_digest,
        "Returns the publication receipt digest."
    ),
    (
        catalog_generation,
        u64,
        catalog_generation,
        "Returns the immutable catalog generation."
    ),
    (
        catalog_digest,
        ObjectDigest,
        catalog_digest,
        "Returns the immutable catalog digest."
    ),
    (cache_id, [u8; 32], cache_id, "Returns the cache identity."),
    (
        cache_generation,
        u64,
        cache_generation,
        "Returns the cache generation."
    ),
    (
        cache_digest,
        ObjectDigest,
        cache_digest,
        "Returns the cache-state digest."
    ),
    (
        disclosure_digest,
        ObjectDigest,
        disclosure_digest,
        "Returns the disclosure-policy digest."
    ),
    (
        materialization_digest,
        ObjectDigest,
        materialization_digest,
        "Returns the materialization digest."
    ),
    (
        verity_measurement_set_digest,
        ObjectDigest,
        verity_measurement_set_digest,
        "Returns the fs-verity measurement-set digest."
    ),
    (
        writer_closure_digest,
        ObjectDigest,
        writer_closure_digest,
        "Returns the writer-closure digest."
    ),
);
proof_accessors!(
    BestEffortReplicaProofV1,
    (
        reconstructibility_digest,
        ObjectDigest,
        reconstructibility_digest,
        "Returns the origin reconstructibility commitment."
    ),
    (replica_id, [u8; 32], replica_id, "Returns the replica ID."),
    (
        replica_generation,
        u64,
        replica_generation,
        "Returns the replica generation."
    ),
    (
        replica_digest,
        ObjectDigest,
        replica_digest,
        "Returns the replica-state digest."
    ),
    (
        cutoff_seconds,
        i64,
        cutoff_seconds,
        "Returns the exact replica cutoff time."
    ),
    (
        checkpoint_generation,
        u64,
        checkpoint_generation,
        "Returns the checkpoint generation."
    ),
    (
        checkpoint_digest,
        ObjectDigest,
        checkpoint_digest,
        "Returns the checkpoint digest."
    ),
    (
        lag_bound_seconds,
        u64,
        lag_bound_seconds,
        "Returns the admitted lag bound."
    ),
    (
        observed_lag_seconds,
        u64,
        observed_lag_seconds,
        "Returns the observed replica lag."
    ),
    (
        access_grant_digest,
        ObjectDigest,
        access_grant_digest,
        "Returns the replica access-grant digest."
    ),
    (degraded, bool, degraded, "Reports degraded replica state."),
);
