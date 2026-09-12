//! Backend-specific SourceProvider proof claims.
//!
//! Every proof is explicit, bounded, and paired with an orthogonal recursive
//! topology commitment. This format records provider claims; backend-specific
//! evidence verifiers decide whether those claims are true.
//!
//! ```text
//! proof-class:u8 || reserved[7]=0 || class-fields || recursive-topology-fields
//! ```

use aos_sandbox_core::ObjectDigest;

use crate::model::{
    MAXIMUM_RECURSIVE_BYTE_COUNT, MAXIMUM_RECURSIVE_DEPTH, MAXIMUM_RECURSIVE_ENTRY_COUNT,
    MAXIMUM_SOURCE_SUBMOUNTS, SourceProviderValidationError, require_digest, require_generation,
    require_nonzero,
};

/// Commits recursive topology independently of backend proof class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecursiveTopologyProofV1 {
    pub(crate) authority_id: [u8; 16],
    pub(crate) generation: u64,
    pub(crate) topology_digest: ObjectDigest,
    pub(crate) entry_count: u64,
    pub(crate) byte_count: u64,
    pub(crate) maximum_depth: u32,
    pub(crate) observed_submounts: u32,
}

impl RecursiveTopologyProofV1 {
    /// Constructs one bounded recursive topology commitment.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderValidationError`] for sentinel authority fields,
    /// zero entries, counts outside the protocol ceilings, or a depth/submount
    /// combination impossible for the root-inclusive entry count.
    pub fn new(
        authority_id: [u8; 16],
        generation: u64,
        topology_digest: ObjectDigest,
        entry_count: u64,
        byte_count: u64,
        maximum_depth: u32,
        observed_submounts: u32,
    ) -> Result<Self, SourceProviderValidationError> {
        require_nonzero("topology authority ID", &authority_id)?;
        require_generation("topology authority", generation)?;
        require_digest("topology digest", topology_digest)?;
        if entry_count == 0
            || entry_count > MAXIMUM_RECURSIVE_ENTRY_COUNT
            || byte_count > MAXIMUM_RECURSIVE_BYTE_COUNT
            || maximum_depth == 0
            || maximum_depth > MAXIMUM_RECURSIVE_DEPTH
            || observed_submounts > MAXIMUM_SOURCE_SUBMOUNTS
            || u64::from(observed_submounts) > entry_count - 1
            || u64::from(maximum_depth) > entry_count
            || maximum_depth > observed_submounts.saturating_add(1)
        {
            return Err(SourceProviderValidationError::InvalidTopology);
        }
        Ok(Self {
            authority_id,
            generation,
            topology_digest,
            entry_count,
            byte_count,
            maximum_depth,
            observed_submounts,
        })
    }

    /// Returns the topology-count authority ID.
    #[must_use]
    pub const fn authority_id(&self) -> [u8; 16] {
        self.authority_id
    }

    /// Returns the topology proof generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the recursive topology digest.
    #[must_use]
    pub const fn topology_digest(&self) -> ObjectDigest {
        self.topology_digest
    }

    /// Returns the recursively reachable entry count.
    #[must_use]
    pub const fn entry_count(&self) -> u64 {
        self.entry_count
    }

    /// Returns the recursively reachable byte count.
    #[must_use]
    pub const fn byte_count(&self) -> u64 {
        self.byte_count
    }

    /// Returns the maximum represented directory depth.
    #[must_use]
    pub const fn maximum_depth(&self) -> u32 {
        self.maximum_depth
    }

    /// Returns the observed recursive submount count.
    #[must_use]
    pub const fn observed_submounts(&self) -> u32 {
        self.observed_submounts
    }
}

/// Carries ZFS snapshot identity and an exact held-snapshot commitment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZfsHeldSnapshotProofV1 {
    pub(crate) storage_handle: [u8; 32],
    pub(crate) storage_version: u64,
    pub(crate) pool_guid: u64,
    pub(crate) dataset_guid: u64,
    pub(crate) snapshot_guid: u64,
    pub(crate) hold_id: [u8; 16],
    pub(crate) hold_generation: u64,
    pub(crate) active_hold_digest: ObjectDigest,
    pub(crate) root_policy_digest: ObjectDigest,
    pub(crate) read_only_content_digest: ObjectDigest,
}

impl ZfsHeldSnapshotProofV1 {
    /// Constructs a ZFS held-snapshot proof claim.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderValidationError`] for zero GUIDs or hold digest.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        storage_handle: [u8; 32],
        storage_version: u64,
        pool_guid: u64,
        dataset_guid: u64,
        snapshot_guid: u64,
        hold_id: [u8; 16],
        hold_generation: u64,
        active_hold_digest: ObjectDigest,
        root_policy_digest: ObjectDigest,
        read_only_content_digest: ObjectDigest,
    ) -> Result<Self, SourceProviderValidationError> {
        require_nonzero("ZFS storage handle", &storage_handle)?;
        require_generation("ZFS storage version", storage_version)?;
        require_generation("ZFS pool GUID", pool_guid)?;
        require_generation("ZFS dataset GUID", dataset_guid)?;
        require_generation("ZFS snapshot GUID", snapshot_guid)?;
        require_nonzero("ZFS hold ID", &hold_id)?;
        require_generation("ZFS hold", hold_generation)?;
        require_digest("ZFS active hold digest", active_hold_digest)?;
        require_digest("ZFS root policy digest", root_policy_digest)?;
        require_digest("ZFS read-only content digest", read_only_content_digest)?;
        Ok(Self {
            storage_handle,
            storage_version,
            pool_guid,
            dataset_guid,
            snapshot_guid,
            hold_id,
            hold_generation,
            active_hold_digest,
            root_policy_digest,
            read_only_content_digest,
        })
    }
}

/// Carries one Storage live-export proof claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalLiveExportProofV1 {
    pub(crate) source_assignment_digest: ObjectDigest,
    pub(crate) owner_sandbox: [u8; 16],
    pub(crate) source_incarnation: [u8; 16],
    pub(crate) export_id: [u8; 16],
    pub(crate) export_generation: u64,
    pub(crate) export_revocation_digest: ObjectDigest,
    pub(crate) export_lease_digest: ObjectDigest,
    pub(crate) consumer_authority_id: [u8; 16],
    pub(crate) consumer_generation: u64,
    pub(crate) kernel_grant_digest: ObjectDigest,
    pub(crate) workspace_id: [u8; 32],
    pub(crate) workspace_digest: ObjectDigest,
}

impl LocalLiveExportProofV1 {
    /// Constructs one exact local live-export proof claim.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderValidationError`] for sentinel identities,
    /// generation, or workspace digest.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_assignment_digest: ObjectDigest,
        owner_sandbox: [u8; 16],
        source_incarnation: [u8; 16],
        export_id: [u8; 16],
        export_generation: u64,
        export_revocation_digest: ObjectDigest,
        export_lease_digest: ObjectDigest,
        consumer_authority_id: [u8; 16],
        consumer_generation: u64,
        kernel_grant_digest: ObjectDigest,
        workspace_id: [u8; 32],
        workspace_digest: ObjectDigest,
    ) -> Result<Self, SourceProviderValidationError> {
        require_digest("source assignment digest", source_assignment_digest)?;
        require_nonzero("export owner sandbox", &owner_sandbox)?;
        require_nonzero("export source incarnation", &source_incarnation)?;
        require_nonzero("export ID", &export_id)?;
        require_generation("export", export_generation)?;
        require_digest("export revocation digest", export_revocation_digest)?;
        require_digest("export lease digest", export_lease_digest)?;
        require_nonzero("export consumer authority ID", &consumer_authority_id)?;
        require_generation("export consumer", consumer_generation)?;
        require_digest("kernel-coupled export grant digest", kernel_grant_digest)?;
        require_nonzero("workspace ID", &workspace_id)?;
        require_digest("workspace digest", workspace_digest)?;
        Ok(Self {
            source_assignment_digest,
            owner_sandbox,
            source_incarnation,
            export_id,
            export_generation,
            export_revocation_digest,
            export_lease_digest,
            consumer_authority_id,
            consumer_generation,
            kernel_grant_digest,
            workspace_id,
            workspace_digest,
        })
    }
}

/// Carries one immutable publisher tree selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImmutablePublisherTreeProofV1 {
    pub(crate) tree_digest: ObjectDigest,
    pub(crate) view_digest: ObjectDigest,
    pub(crate) publication_generation: u64,
    pub(crate) publication_receipt_digest: ObjectDigest,
    pub(crate) catalog_generation: u64,
    pub(crate) catalog_digest: ObjectDigest,
    pub(crate) cache_id: [u8; 32],
    pub(crate) cache_generation: u64,
    pub(crate) cache_digest: ObjectDigest,
    pub(crate) disclosure_digest: ObjectDigest,
    pub(crate) materialization_digest: ObjectDigest,
    pub(crate) verity_measurement_set_digest: ObjectDigest,
    pub(crate) writer_closure_digest: ObjectDigest,
}

impl ImmutablePublisherTreeProofV1 {
    /// Constructs one exact immutable-publisher tree proof claim.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderValidationError`] for sentinel fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tree_digest: ObjectDigest,
        view_digest: ObjectDigest,
        publication_generation: u64,
        publication_receipt_digest: ObjectDigest,
        catalog_generation: u64,
        catalog_digest: ObjectDigest,
        cache_id: [u8; 32],
        cache_generation: u64,
        cache_digest: ObjectDigest,
        disclosure_digest: ObjectDigest,
        materialization_digest: ObjectDigest,
        verity_measurement_set_digest: ObjectDigest,
        writer_closure_digest: ObjectDigest,
    ) -> Result<Self, SourceProviderValidationError> {
        require_digest("immutable tree digest", tree_digest)?;
        require_digest("immutable view digest", view_digest)?;
        require_generation("immutable publication", publication_generation)?;
        require_digest(
            "immutable publication receipt digest",
            publication_receipt_digest,
        )?;
        require_generation("immutable catalog", catalog_generation)?;
        require_digest("immutable catalog digest", catalog_digest)?;
        require_nonzero("immutable cache ID", &cache_id)?;
        require_generation("immutable cache", cache_generation)?;
        require_digest("immutable cache digest", cache_digest)?;
        require_digest("immutable disclosure digest", disclosure_digest)?;
        require_digest("immutable materialization digest", materialization_digest)?;
        require_digest(
            "immutable fs-verity measurement-set digest",
            verity_measurement_set_digest,
        )?;
        require_digest("immutable writer-closure digest", writer_closure_digest)?;
        Ok(Self {
            tree_digest,
            view_digest,
            publication_generation,
            publication_receipt_digest,
            catalog_generation,
            catalog_digest,
            cache_id,
            cache_generation,
            cache_digest,
            disclosure_digest,
            materialization_digest,
            verity_measurement_set_digest,
            writer_closure_digest,
        })
    }
}

/// Carries one explicitly non-authoritative best-effort replica selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BestEffortReplicaProofV1 {
    pub(crate) reconstructibility_digest: ObjectDigest,
    pub(crate) replica_id: [u8; 32],
    pub(crate) replica_generation: u64,
    pub(crate) replica_digest: ObjectDigest,
    pub(crate) cutoff_seconds: i64,
    pub(crate) checkpoint_generation: u64,
    pub(crate) checkpoint_digest: ObjectDigest,
    pub(crate) lag_bound_seconds: u64,
    pub(crate) observed_lag_seconds: u64,
    pub(crate) access_grant_digest: ObjectDigest,
    pub(crate) degraded: bool,
}

impl BestEffortReplicaProofV1 {
    /// Constructs one exact best-effort replica proof claim.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderValidationError`] for sentinel fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reconstructibility_digest: ObjectDigest,
        replica_id: [u8; 32],
        replica_generation: u64,
        replica_digest: ObjectDigest,
        cutoff_seconds: i64,
        checkpoint_generation: u64,
        checkpoint_digest: ObjectDigest,
        lag_bound_seconds: u64,
        observed_lag_seconds: u64,
        access_grant_digest: ObjectDigest,
        degraded: bool,
    ) -> Result<Self, SourceProviderValidationError> {
        require_digest(
            "replica reconstructibility digest",
            reconstructibility_digest,
        )?;
        require_nonzero("replica ID", &replica_id)?;
        require_generation("replica", replica_generation)?;
        require_digest("replica digest", replica_digest)?;
        if cutoff_seconds < 0 || observed_lag_seconds > lag_bound_seconds {
            return Err(SourceProviderValidationError::InvalidInterval(
                "best-effort replica",
            ));
        }
        require_generation("replica checkpoint", checkpoint_generation)?;
        require_digest("replica checkpoint digest", checkpoint_digest)?;
        require_digest("replica access grant digest", access_grant_digest)?;
        Ok(Self {
            reconstructibility_digest,
            replica_id,
            replica_generation,
            replica_digest,
            cutoff_seconds,
            checkpoint_generation,
            checkpoint_digest,
            lag_bound_seconds,
            observed_lag_seconds,
            access_grant_digest,
            degraded,
        })
    }
}

/// Carries one closed backend proof class plus orthogonal recursive topology.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceProviderProofV1 {
    /// ZFS held-snapshot source.
    ZfsHeldSnapshot {
        /// Backend-specific held-snapshot identity.
        proof: ZfsHeldSnapshotProofV1,
        /// Recursive topology/count authority.
        topology: RecursiveTopologyProofV1,
    },
    /// Storage local live export.
    LocalLiveExport {
        /// Backend-specific export identity.
        proof: LocalLiveExportProofV1,
        /// Recursive topology/count authority.
        topology: RecursiveTopologyProofV1,
    },
    /// Immutable publisher tree.
    ImmutablePublisherTree {
        /// Backend-specific publication identity.
        proof: ImmutablePublisherTreeProofV1,
        /// Recursive topology/count authority.
        topology: RecursiveTopologyProofV1,
    },
    /// Explicitly best-effort replica.
    BestEffortReplica {
        /// Backend-specific replica identity.
        proof: BestEffortReplicaProofV1,
        /// Recursive topology/count authority.
        topology: RecursiveTopologyProofV1,
    },
}

impl SourceProviderProofV1 {
    /// Returns the closed proof-class code.
    #[must_use]
    pub const fn class_code(&self) -> u8 {
        match self {
            Self::ZfsHeldSnapshot { .. } => 1,
            Self::LocalLiveExport { .. } => 2,
            Self::ImmutablePublisherTree { .. } => 3,
            Self::BestEffortReplica { .. } => 4,
        }
    }

    /// Returns the single capability bit representing this proof class.
    #[must_use]
    pub const fn capability_bit(&self) -> u8 {
        1 << (self.class_code() - 1)
    }

    /// Reports whether this proof requires a kernel-coupled grant.
    #[must_use]
    pub const fn requires_kernel_coupled(&self) -> bool {
        matches!(self, Self::LocalLiveExport { .. })
    }

    /// Returns the orthogonal recursive topology commitment.
    #[must_use]
    pub const fn topology(&self) -> &RecursiveTopologyProofV1 {
        match self {
            Self::ZfsHeldSnapshot { topology, .. }
            | Self::LocalLiveExport { topology, .. }
            | Self::ImmutablePublisherTree { topology, .. }
            | Self::BestEffortReplica { topology, .. } => topology,
        }
    }
}
