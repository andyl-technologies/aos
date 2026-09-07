//! Versioned resolved-catalog semantics for storage authority.
//!
//! The eventual root storage service constructs these bounded bytes from its
//! trusted local catalog. Names are never accepted without an explicit managed
//! pool/root, and every existing ZFS object carries the nonzero GUID observed
//! by that catalog. Only [`CatalogBindingV1`] crosses into portable signed
//! semantics: raw names, GUIDs, and backend expressions remain node-local.
//!
//! Planned create/clone/snapshot targets cannot have a ZFS GUID before the
//! effect. They therefore bind their exact future name and the derived
//! [`PostconditionPolicyV1::CaptureDataset`] or snapshot-capture rule; the source or managed parent
//! still carries its exact pre-effect GUID. The service must persist the newly
//! observed GUID before publishing a resolved object.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::semantics::CatalogBindingV1;
use sha2::{Digest as _, Sha256};

const FORMAT_MAGIC: &[u8; 8] = b"AOSSCAT1";
const FORMAT_VERSION: u16 = 1;
const DIGEST_DOMAIN: &[u8] = b"aos-sandbox-storage-resolved-catalog-v1\0";
const MAXIMUM_NAME_BYTES: usize = 255;
const MAXIMUM_CANONICAL_BYTES: usize = 16 * 1024;

/// Reports a resolved-catalog value that is unsafe or noncanonical.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CatalogSemanticError {
    /// A pool, managed root, dataset, or snapshot name is invalid.
    #[error("storage catalog object name is outside the managed root or grammar")]
    InvalidName,
    /// An existing catalog object has the reserved zero GUID.
    #[error("storage catalog object GUID is zero")]
    InvalidGuid,
    /// A generation, domain digest, hold identifier, or numeric policy uses a sentinel.
    #[error("storage catalog semantics contain a reserved value")]
    InvalidValue,
    /// A plan combines objects from different managed roots or incompatible origins.
    #[error("storage catalog plan objects do not share one valid managed root")]
    InconsistentPlan,
    /// Canonical bytes exceeded the fixed V1 ceiling.
    #[error("resolved storage catalog semantics exceed the V1 byte ceiling")]
    EncodingTooLarge,
}

/// Identifies the kind of one exact ZFS catalog object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogObjectKind {
    /// Writable or policy-bearing ZFS filesystem dataset.
    Dataset,
    /// Immutable ZFS snapshot.
    Snapshot,
}

/// Defines the pool and dataset prefix exclusively managed by storage V1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedDatasetRoot {
    pool: String,
    dataset_prefix: String,
    guid: u64,
}

impl ManagedDatasetRoot {
    /// Validates an explicit pool/root pair and its catalogued nonzero GUID.
    ///
    /// The root must be a child dataset such as `tank/aos-sandboxes`, not the
    /// pool itself. Effects may target only strict descendants of this root.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogSemanticError`] for invalid grammar, a mismatched pool,
    /// an oversized name, or a zero GUID.
    pub fn from_catalog(
        pool: &str,
        dataset_prefix: &str,
        guid: u64,
    ) -> Result<Self, CatalogSemanticError> {
        if guid == 0 {
            return Err(CatalogSemanticError::InvalidGuid);
        }
        if !valid_component(pool)
            || pool.contains(['/', '@', '#'])
            || !valid_dataset_name(dataset_prefix)
            || dataset_prefix.split('/').next() != Some(pool)
            || dataset_prefix.split('/').count() < 2
        {
            return Err(CatalogSemanticError::InvalidName);
        }
        Ok(Self {
            pool: pool.to_owned(),
            dataset_prefix: dataset_prefix.to_owned(),
            guid,
        })
    }

    /// Returns the exact managed ZFS pool name.
    #[must_use]
    pub fn pool(&self) -> &str {
        &self.pool
    }

    /// Returns the exact managed dataset prefix.
    #[must_use]
    pub fn dataset_prefix(&self) -> &str {
        &self.dataset_prefix
    }

    /// Returns the catalogued ZFS GUID of the managed root.
    #[must_use]
    pub const fn guid(&self) -> u64 {
        self.guid
    }
}

/// Identifies one existing dataset resolved beneath a managed root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedDataset {
    root: ManagedDatasetRoot,
    name: String,
    guid: u64,
    storage_handle: [u8; 32],
    domains: StorageDomainsV1,
}

impl ResolvedDataset {
    /// Validates a catalog dataset as a strict child of `root` with nonzero GUID.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogSemanticError`] when the name is unsafe or outside the
    /// configured root, or when `guid` is zero.
    pub fn from_catalog(
        root: ManagedDatasetRoot,
        name: &str,
        guid: u64,
        storage_handle: [u8; 32],
        domains: StorageDomainsV1,
    ) -> Result<Self, CatalogSemanticError> {
        if guid == 0 {
            return Err(CatalogSemanticError::InvalidGuid);
        }
        if storage_handle == [0; 32] {
            return Err(CatalogSemanticError::InvalidValue);
        }
        validate_descendant(&root, name)?;
        Ok(Self {
            root,
            name: name.to_owned(),
            guid,
            storage_handle,
            domains,
        })
    }

    /// Returns the configured managed root.
    #[must_use]
    pub const fn root(&self) -> &ManagedDatasetRoot {
        &self.root
    }

    /// Returns the exact dataset name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the exact catalogued ZFS GUID.
    #[must_use]
    pub const fn guid(&self) -> u64 {
        self.guid
    }

    /// Returns the exact broker resource handle resolved to this dataset.
    #[must_use]
    pub const fn storage_handle(&self) -> [u8; 32] {
        self.storage_handle
    }

    /// Returns the policy domains catalogued with this dataset.
    #[must_use]
    pub const fn domains(&self) -> StorageDomainsV1 {
        self.domains
    }
}

/// Identifies one existing immutable snapshot with its exact ZFS GUID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedSnapshot {
    dataset: ResolvedDataset,
    component: String,
    rendered: String,
    guid: u64,
    version_handle: [u8; 32],
}

impl ResolvedSnapshot {
    /// Validates a catalog snapshot component and nonzero GUID.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogSemanticError`] for invalid grammar, an oversized full
    /// identity, or a zero GUID.
    pub fn from_catalog(
        dataset: ResolvedDataset,
        component: &str,
        guid: u64,
        version_handle: [u8; 32],
    ) -> Result<Self, CatalogSemanticError> {
        if guid == 0 {
            return Err(CatalogSemanticError::InvalidGuid);
        }
        if version_handle == [0; 32] {
            return Err(CatalogSemanticError::InvalidValue);
        }
        validate_snapshot_component(dataset.name(), component)?;
        Ok(Self {
            rendered: format!("{}@{component}", dataset.name()),
            dataset,
            component: component.to_owned(),
            guid,
            version_handle,
        })
    }

    /// Returns the resolved owning dataset.
    #[must_use]
    pub const fn dataset(&self) -> &ResolvedDataset {
        &self.dataset
    }

    /// Returns the exact snapshot component.
    #[must_use]
    pub fn component(&self) -> &str {
        &self.component
    }

    /// Returns the exact `dataset@snapshot` identity.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.rendered
    }

    /// Returns the exact catalogued snapshot GUID.
    #[must_use]
    pub const fn guid(&self) -> u64 {
        self.guid
    }

    /// Returns the exact broker version handle resolved to this snapshot.
    #[must_use]
    pub const fn version_handle(&self) -> [u8; 32] {
        self.version_handle
    }
}

/// Reserves the exact future name of a dataset beneath a managed root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedDataset {
    root: ManagedDatasetRoot,
    name: String,
    domains: StorageDomainsV1,
}

impl PlannedDataset {
    /// Validates an exact future dataset name beneath `root`.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogSemanticError::InvalidName`] for an unsafe or
    /// out-of-root destination.
    pub fn from_catalog(
        root: ManagedDatasetRoot,
        name: &str,
        domains: StorageDomainsV1,
    ) -> Result<Self, CatalogSemanticError> {
        validate_descendant(&root, name)?;
        Ok(Self {
            root,
            name: name.to_owned(),
            domains,
        })
    }

    /// Returns the configured managed root.
    #[must_use]
    pub const fn root(&self) -> &ManagedDatasetRoot {
        &self.root
    }

    /// Returns the exact future dataset name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the destination policy domains selected by the catalog.
    #[must_use]
    pub const fn domains(&self) -> StorageDomainsV1 {
        self.domains
    }
}

/// Reserves the exact future name of a snapshot of an existing dataset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedSnapshot {
    dataset: ResolvedDataset,
    component: String,
    rendered: String,
}

impl PlannedSnapshot {
    /// Validates an exact future snapshot component.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogSemanticError::InvalidName`] for invalid grammar or an
    /// oversized complete snapshot identity.
    pub fn from_catalog(
        dataset: ResolvedDataset,
        component: &str,
    ) -> Result<Self, CatalogSemanticError> {
        validate_snapshot_component(dataset.name(), component)?;
        Ok(Self {
            rendered: format!("{}@{component}", dataset.name()),
            dataset,
            component: component.to_owned(),
        })
    }

    /// Returns the resolved source dataset.
    #[must_use]
    pub const fn dataset(&self) -> &ResolvedDataset {
        &self.dataset
    }

    /// Returns the future snapshot component.
    #[must_use]
    pub fn component(&self) -> &str {
        &self.component
    }

    /// Returns the exact future `dataset@snapshot` identity.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.rendered
    }
}

/// Names one durable hold independently of any request operation ID.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HoldId([u8; 16]);

impl HoldId {
    /// Constructs a durable hold identifier from exact nonzero bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogSemanticError::InvalidValue`] for the zero sentinel.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, CatalogSemanticError> {
        if bytes == [0; 16] {
            Err(CatalogSemanticError::InvalidValue)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Returns exact durable identifier bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Proves that one durable hold was observed on an exact snapshot GUID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveHoldEvidence {
    snapshot_guid: u64,
    hold_id: HoldId,
}

impl ActiveHoldEvidence {
    /// Records catalog evidence for an observed exact hold.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogSemanticError::InvalidGuid`] for a zero snapshot GUID.
    pub fn from_catalog(snapshot_guid: u64, hold_id: HoldId) -> Result<Self, CatalogSemanticError> {
        if snapshot_guid == 0 {
            Err(CatalogSemanticError::InvalidGuid)
        } else {
            Ok(Self {
                snapshot_guid,
                hold_id,
            })
        }
    }

    /// Returns the observed snapshot GUID.
    #[must_use]
    pub const fn snapshot_guid(self) -> u64 {
        self.snapshot_guid
    }

    /// Returns the observed durable hold identity.
    #[must_use]
    pub const fn hold_id(self) -> HoldId {
        self.hold_id
    }
}

/// Binds policy partitions that prevent cross-domain catalog substitution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageDomainsV1 {
    /// Disclosure-policy domain digest.
    disclosure: ObjectDigest,
    /// Encryption-policy and key-generation domain digest.
    encryption: ObjectDigest,
    /// Aggregate accounting domain digest.
    accounting: ObjectDigest,
    /// Snapshot/hold retention domain digest.
    retention: ObjectDigest,
}

impl StorageDomainsV1 {
    /// Validates four explicit nonzero domain commitments.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogSemanticError::InvalidValue`] when any digest is zero.
    pub fn new(
        disclosure: ObjectDigest,
        encryption: ObjectDigest,
        accounting: ObjectDigest,
        retention: ObjectDigest,
    ) -> Result<Self, CatalogSemanticError> {
        let value = Self {
            disclosure,
            encryption,
            accounting,
            retention,
        };
        if [disclosure, encryption, accounting, retention]
            .iter()
            .any(|digest| digest.as_bytes() == &[0; 32])
        {
            Err(CatalogSemanticError::InvalidValue)
        } else {
            Ok(value)
        }
    }

    /// Returns the disclosure-policy domain digest.
    #[must_use]
    pub const fn disclosure(self) -> ObjectDigest {
        self.disclosure
    }

    /// Returns the encryption-policy and key-generation domain digest.
    #[must_use]
    pub const fn encryption(self) -> ObjectDigest {
        self.encryption
    }

    /// Returns the aggregate-accounting domain digest.
    #[must_use]
    pub const fn accounting(self) -> ObjectDigest {
        self.accounting
    }

    /// Returns the snapshot/hold retention domain digest.
    #[must_use]
    pub const fn retention(self) -> ObjectDigest {
        self.retention
    }
}

/// Selects the explicit physical-space reservation rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationPolicy {
    /// Makes no per-dataset physical reservation.
    None,
    /// Reserves exactly the stated nonzero byte count.
    Exact(u64),
}

/// Binds aggregate accounting policy to an exact project-ancestor dataset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectAncestorPolicyV1 {
    dataset: ResolvedDataset,
    quota_bytes: u64,
    filesystem_limit: u64,
    snapshot_limit: u64,
}

impl ProjectAncestorPolicyV1 {
    /// Constructs finite aggregate limits for a resolved project ancestor.
    ///
    /// This policy means the ordinary ZFS `quota`, `filesystem_limit`, and
    /// `snapshot_limit` properties on `dataset`; it does not mean ZFS
    /// `projectquota` accounting by numeric project ID.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogSemanticError::InvalidValue`] for any zero limit.
    pub fn new(
        dataset: ResolvedDataset,
        quota_bytes: u64,
        filesystem_limit: u64,
        snapshot_limit: u64,
    ) -> Result<Self, CatalogSemanticError> {
        if quota_bytes == 0 || filesystem_limit == 0 || snapshot_limit == 0 {
            Err(CatalogSemanticError::InvalidValue)
        } else {
            Ok(Self {
                dataset,
                quota_bytes,
                filesystem_limit,
                snapshot_limit,
            })
        }
    }

    /// Returns the exact resolved project-ancestor dataset.
    #[must_use]
    pub const fn dataset(&self) -> &ResolvedDataset {
        &self.dataset
    }

    /// Returns the aggregate hard byte quota.
    #[must_use]
    pub const fn quota_bytes(&self) -> u64 {
        self.quota_bytes
    }

    /// Returns the aggregate descendant-filesystem count limit.
    #[must_use]
    pub const fn filesystem_limit(&self) -> u64 {
        self.filesystem_limit
    }

    /// Returns the aggregate descendant-snapshot count limit.
    #[must_use]
    pub const fn snapshot_limit(&self) -> u64 {
        self.snapshot_limit
    }
}

/// Fixes private ZFS accounting properties for one workspace child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkspaceSpacePolicyV1 {
    refquota_bytes: u64,
    reservation: ReservationPolicy,
}

impl WorkspaceSpacePolicyV1 {
    /// Validates the complete finite workspace accounting policy.
    ///
    /// `refquota` is the private referenced-byte ceiling. Reservation is
    /// explicit rather than inferred from that quota. Aggregate limits belong
    /// to [`ProjectAncestorPolicyV1`], never to this child policy.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogSemanticError::InvalidValue`] for zero limits or a
    /// reservation greater than the private refquota.
    pub fn new(
        refquota_bytes: u64,
        reservation: ReservationPolicy,
    ) -> Result<Self, CatalogSemanticError> {
        let reservation_valid = match reservation {
            ReservationPolicy::None => true,
            ReservationPolicy::Exact(bytes) => bytes != 0 && bytes <= refquota_bytes,
        };
        if refquota_bytes == 0 || !reservation_valid {
            return Err(CatalogSemanticError::InvalidValue);
        }
        Ok(Self {
            refquota_bytes,
            reservation,
        })
    }

    /// Returns the private referenced-byte quota.
    #[must_use]
    pub const fn refquota_bytes(self) -> u64 {
        self.refquota_bytes
    }

    /// Returns the explicit physical reservation rule.
    #[must_use]
    pub const fn reservation(self) -> ReservationPolicy {
        self.reservation
    }
}

/// States the mandatory observation after one fixed mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PostconditionPolicyV1 {
    /// Captures a new dataset GUID and verifies its exact private properties and origin.
    CaptureDataset {
        /// Exact created dataset name.
        name: String,
        /// Required private accounting properties.
        space: WorkspaceSpacePolicyV1,
        /// Exact clone origin name, or `None` for an empty workspace.
        origin_name: Option<String>,
        /// Exact clone origin GUID, or zero for an empty workspace.
        origin_guid: u64,
        /// Required origin hold, or `None` for an empty workspace.
        origin_hold: Option<HoldId>,
    },
    /// Captures a new snapshot GUID at the exact name and source GUID.
    CaptureSnapshot {
        /// Exact created snapshot name.
        name: String,
        /// Exact source dataset GUID.
        source_guid: u64,
    },
    /// Verifies an exact durable hold is present or absent on the same GUID.
    HoldState {
        /// Exact snapshot name.
        name: String,
        /// Exact snapshot GUID.
        guid: u64,
        /// Durable hold identity.
        hold_id: HoldId,
        /// Required resulting presence state.
        present: bool,
    },
    /// Verifies the same dataset GUID and exact private properties.
    DatasetProperties {
        /// Exact dataset name.
        name: String,
        /// Exact dataset GUID.
        guid: u64,
        /// Required private accounting properties.
        space: WorkspaceSpacePolicyV1,
    },
    /// Verifies that the exact name/GUID pair is absent.
    Absent {
        /// Exact former object name.
        name: String,
        /// Kind of the destroyed object.
        kind: CatalogObjectKind,
        /// Exact pre-effect ZFS GUID.
        guid: u64,
    },
}

/// Describes every catalog-resolved input and policy for one storage effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CatalogPlanV1 {
    /// Creates one exact private workspace destination.
    CreateWorkspace {
        /// Reserved destination beneath the managed root.
        destination: PlannedDataset,
        /// Private child accounting policy.
        space: WorkspaceSpacePolicyV1,
        /// Resolved aggregate project-ancestor policy.
        ancestor: ProjectAncestorPolicyV1,
    },
    /// Creates one exact immutable version of an existing dataset.
    Snapshot {
        /// Existing source with its verified GUID.
        source: ResolvedDataset,
        /// Reserved snapshot name bound to the same source.
        destination: PlannedSnapshot,
    },
    /// Adds a durable hold to an existing exact snapshot.
    HoldSnapshot {
        /// Existing immutable object and GUID.
        snapshot: ResolvedSnapshot,
        /// Durable hold identity, independent of request retries.
        hold_id: HoldId,
    },
    /// Releases the same durable hold from an existing exact snapshot.
    ReleaseHold {
        /// Existing immutable object and GUID.
        snapshot: ResolvedSnapshot,
        /// Exact hold identity originally acquired.
        hold_id: HoldId,
    },
    /// Clones a held immutable origin into one exact private workspace.
    Clone {
        /// Exact immutable origin and GUID.
        source: Box<ResolvedSnapshot>,
        /// Required durable origin hold.
        origin_hold: ActiveHoldEvidence,
        /// Reserved clone destination beneath the same managed root.
        destination: PlannedDataset,
        /// Private child accounting policy.
        space: WorkspaceSpacePolicyV1,
        /// Resolved aggregate project-ancestor policy.
        ancestor: ProjectAncestorPolicyV1,
    },
    /// Replaces accounting properties on one exact existing dataset.
    SetQuota {
        /// Existing target and GUID.
        dataset: ResolvedDataset,
        /// Complete replacement private child accounting policy.
        space: WorkspaceSpacePolicyV1,
        /// Resolved aggregate project-ancestor policy.
        ancestor: ProjectAncestorPolicyV1,
    },
    /// Destroys one exact existing dataset, never recursively.
    DestroyDataset {
        /// Existing target and GUID.
        dataset: ResolvedDataset,
    },
    /// Destroys one exact existing snapshot, never recursively.
    DestroySnapshot {
        /// Existing target and GUID.
        snapshot: ResolvedSnapshot,
    },
}

impl CatalogPlanV1 {
    fn domains(&self) -> StorageDomainsV1 {
        match self {
            Self::CreateWorkspace { destination, .. } | Self::Clone { destination, .. } => {
                destination.domains()
            }
            Self::Snapshot { source, .. } => source.domains(),
            Self::HoldSnapshot { snapshot, .. }
            | Self::ReleaseHold { snapshot, .. }
            | Self::DestroySnapshot { snapshot } => snapshot.dataset().domains(),
            Self::SetQuota { dataset, .. } | Self::DestroyDataset { dataset } => dataset.domains(),
        }
    }

    /// Returns the mandatory postcondition derived from the operation.
    #[must_use]
    pub fn postcondition(&self) -> PostconditionPolicyV1 {
        match self {
            Self::CreateWorkspace {
                destination, space, ..
            } => PostconditionPolicyV1::CaptureDataset {
                name: destination.name().to_owned(),
                space: *space,
                origin_name: None,
                origin_guid: 0,
                origin_hold: None,
            },
            Self::Clone {
                source,
                origin_hold,
                destination,
                space,
                ..
            } => PostconditionPolicyV1::CaptureDataset {
                name: destination.name().to_owned(),
                space: *space,
                origin_name: Some(source.name().to_owned()),
                origin_guid: source.guid(),
                origin_hold: Some(origin_hold.hold_id()),
            },
            Self::Snapshot {
                source,
                destination,
            } => PostconditionPolicyV1::CaptureSnapshot {
                name: destination.name().to_owned(),
                source_guid: source.guid(),
            },
            Self::HoldSnapshot { snapshot, hold_id } => PostconditionPolicyV1::HoldState {
                name: snapshot.name().to_owned(),
                guid: snapshot.guid,
                hold_id: *hold_id,
                present: true,
            },
            Self::ReleaseHold { snapshot, hold_id } => PostconditionPolicyV1::HoldState {
                name: snapshot.name().to_owned(),
                guid: snapshot.guid,
                hold_id: *hold_id,
                present: false,
            },
            Self::SetQuota { dataset, space, .. } => PostconditionPolicyV1::DatasetProperties {
                name: dataset.name().to_owned(),
                guid: dataset.guid,
                space: *space,
            },
            Self::DestroyDataset { dataset } => PostconditionPolicyV1::Absent {
                name: dataset.name().to_owned(),
                kind: CatalogObjectKind::Dataset,
                guid: dataset.guid,
            },
            Self::DestroySnapshot { snapshot } => PostconditionPolicyV1::Absent {
                name: snapshot.name().to_owned(),
                kind: CatalogObjectKind::Snapshot,
                guid: snapshot.guid,
            },
        }
    }

    fn root(&self) -> &ManagedDatasetRoot {
        match self {
            Self::CreateWorkspace { destination, .. } | Self::Clone { destination, .. } => {
                destination.root()
            }
            Self::Snapshot { source, .. } => source.root(),
            Self::HoldSnapshot { snapshot, .. }
            | Self::ReleaseHold { snapshot, .. }
            | Self::DestroySnapshot { snapshot } => snapshot.dataset().root(),
            Self::SetQuota { dataset, .. } | Self::DestroyDataset { dataset } => dataset.root(),
        }
    }
}

/// Carries exact canonical resolved-catalog bytes and their storage-domain digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedCatalogCommitmentV1 {
    generation: u64,
    domains: StorageDomainsV1,
    plan: CatalogPlanV1,
    bytes: Vec<u8>,
    digest: ObjectDigest,
    binding: CatalogBindingV1,
}

impl ResolvedCatalogCommitmentV1 {
    /// Canonicalizes one fully resolved catalog plan.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogSemanticError`] for generation zero, mismatched roots
    /// or snapshot origins, or an internal canonical byte-bound violation.
    pub fn new(
        generation: u64,
        domains: StorageDomainsV1,
        plan: CatalogPlanV1,
    ) -> Result<Self, CatalogSemanticError> {
        if generation == 0 {
            return Err(CatalogSemanticError::InvalidValue);
        }
        validate_plan(&plan)?;
        if domains != plan.domains() {
            return Err(CatalogSemanticError::InconsistentPlan);
        }
        let bytes = encode_plan(generation, domains, &plan)?;
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_DOMAIN);
        hasher.update(&bytes);
        let digest = ObjectDigest::from_bytes(hasher.finalize().into());
        let binding = CatalogBindingV1::from_publisher(generation, digest)
            .map_err(|_| CatalogSemanticError::InvalidValue)?;
        Ok(Self {
            generation,
            domains,
            plan,
            bytes,
            digest,
            binding,
        })
    }

    /// Returns the exact catalog generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the four policy-domain commitments.
    #[must_use]
    pub const fn domains(&self) -> StorageDomainsV1 {
        self.domains
    }

    /// Returns the typed effect plan.
    #[must_use]
    pub const fn plan(&self) -> &CatalogPlanV1 {
        &self.plan
    }

    /// Returns exact versioned node-local bytes for persistence and recomputation.
    ///
    /// These bytes contain backend identities and must not enter a portable
    /// signed plan or multi-node protocol.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the storage-specific digest of the exact canonical bytes.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Returns the opaque generation/digest association used by portable authority.
    #[must_use]
    pub const fn binding(&self) -> CatalogBindingV1 {
        self.binding
    }

    /// Checks that persisted node-local bytes retain their exact digest binding.
    pub(crate) fn authenticates_persisted_bytes(binding: CatalogBindingV1, bytes: &[u8]) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_DOMAIN);
        hasher.update(bytes);
        ObjectDigest::from_bytes(hasher.finalize().into()) == binding.digest()
            && encoded_generation(bytes) == Some(binding.generation())
    }
}

fn encoded_generation(bytes: &[u8]) -> Option<u64> {
    // V1 starts with fixed fields 1 (magic), 2 (version), then 3 (generation).
    let generation_offset = 5 + FORMAT_MAGIC.len() + 5 + 2;
    let field = bytes.get(generation_offset..generation_offset.checked_add(13)?)?;
    if field.first().copied() != Some(3) || field.get(1..5)? != 8_u32.to_be_bytes() {
        return None;
    }
    Some(u64::from_be_bytes(field.get(5..13)?.try_into().ok()?))
}

fn validate_plan(plan: &CatalogPlanV1) -> Result<(), CatalogSemanticError> {
    match plan {
        CatalogPlanV1::CreateWorkspace {
            destination,
            ancestor,
            space,
        } if !same_project_ancestry(destination.root(), destination.name(), ancestor)
            || destination.domains() != ancestor.dataset().domains()
            || space.refquota_bytes() > ancestor.quota_bytes() =>
        {
            Err(CatalogSemanticError::InconsistentPlan)
        }
        CatalogPlanV1::Snapshot {
            source,
            destination,
        } if source != destination.dataset() => Err(CatalogSemanticError::InconsistentPlan),
        CatalogPlanV1::Clone {
            source,
            destination,
            ancestor,
            origin_hold,
            space,
        } if source.dataset().root() != destination.root()
            || source.dataset().name() == destination.name()
            || source.dataset().domains() != destination.domains()
            || origin_hold.snapshot_guid() != source.guid()
            || space.refquota_bytes() > ancestor.quota_bytes() =>
        {
            Err(CatalogSemanticError::InconsistentPlan)
        }
        CatalogPlanV1::Clone {
            destination,
            ancestor,
            ..
        } if !same_project_ancestry(destination.root(), destination.name(), ancestor)
            || destination.domains() != ancestor.dataset().domains() =>
        {
            Err(CatalogSemanticError::InconsistentPlan)
        }
        CatalogPlanV1::SetQuota {
            dataset,
            ancestor,
            space,
        } if !same_project_ancestry(dataset.root(), dataset.name(), ancestor)
            || dataset.domains() != ancestor.dataset().domains()
            || space.refquota_bytes() > ancestor.quota_bytes() =>
        {
            Err(CatalogSemanticError::InconsistentPlan)
        }
        _ => Ok(()),
    }
}

fn same_project_ancestry(
    root: &ManagedDatasetRoot,
    workspace_name: &str,
    ancestor: &ProjectAncestorPolicyV1,
) -> bool {
    if ancestor.dataset.root() != root {
        return false;
    }
    let mut prefix = String::with_capacity(ancestor.dataset.name().len() + 1);
    prefix.push_str(ancestor.dataset.name());
    prefix.push('/');
    workspace_name.starts_with(&prefix)
}

fn encode_plan(
    generation: u64,
    domains: StorageDomainsV1,
    plan: &CatalogPlanV1,
) -> Result<Vec<u8>, CatalogSemanticError> {
    let mut encoder = Encoder::new();
    encoder.field(1, FORMAT_MAGIC)?;
    encoder.field(2, &FORMAT_VERSION.to_be_bytes())?;
    encoder.field(3, &generation.to_be_bytes())?;
    let root = plan.root();
    encoder.field(4, root.pool.as_bytes())?;
    encoder.field(5, root.dataset_prefix.as_bytes())?;
    encoder.field(6, &root.guid.to_be_bytes())?;
    encoder.field(7, domains.disclosure.as_bytes())?;
    encoder.field(8, domains.encryption.as_bytes())?;
    encoder.field(9, domains.accounting.as_bytes())?;
    encoder.field(10, domains.retention.as_bytes())?;
    encode_operation(&mut encoder, plan)?;
    encode_postcondition(&mut encoder, &plan.postcondition())?;
    Ok(encoder.finish())
}

fn encode_operation(
    encoder: &mut Encoder,
    plan: &CatalogPlanV1,
) -> Result<(), CatalogSemanticError> {
    let (code, primary_name, primary_guid, destination_name, hold, space, ancestor) = match plan {
        CatalogPlanV1::CreateWorkspace {
            destination,
            space,
            ancestor,
        } => (
            1,
            "",
            0,
            destination.name(),
            None,
            Some(*space),
            Some(ancestor),
        ),
        CatalogPlanV1::Snapshot {
            source,
            destination,
        } => (
            2,
            source.name(),
            source.guid(),
            destination.name(),
            None,
            None,
            None,
        ),
        CatalogPlanV1::HoldSnapshot { snapshot, hold_id } => (
            3,
            snapshot.name(),
            snapshot.guid(),
            "",
            Some(*hold_id),
            None,
            None,
        ),
        CatalogPlanV1::ReleaseHold { snapshot, hold_id } => (
            4,
            snapshot.name(),
            snapshot.guid(),
            "",
            Some(*hold_id),
            None,
            None,
        ),
        CatalogPlanV1::Clone {
            source,
            origin_hold,
            destination,
            space,
            ancestor,
        } => (
            5,
            source.name(),
            source.guid(),
            destination.name(),
            Some(origin_hold.hold_id()),
            Some(*space),
            Some(ancestor),
        ),
        CatalogPlanV1::SetQuota {
            dataset,
            space,
            ancestor,
        } => (
            6,
            dataset.name(),
            dataset.guid(),
            "",
            None,
            Some(*space),
            Some(ancestor),
        ),
        CatalogPlanV1::DestroyDataset { dataset } => {
            (7, dataset.name(), dataset.guid(), "", None, None, None)
        }
        CatalogPlanV1::DestroySnapshot { snapshot } => {
            (8, snapshot.name(), snapshot.guid(), "", None, None, None)
        }
    };
    encoder.field(11, &[code])?;
    encoder.field(12, primary_name.as_bytes())?;
    encoder.field(13, &primary_guid.to_be_bytes())?;
    encoder.field(14, destination_name.as_bytes())?;
    encoder.field(
        15,
        hold.map(HoldId::as_bytes)
            .as_ref()
            .map_or(&[], <[u8; 16]>::as_slice),
    )?;
    encode_space(encoder, space, ancestor)?;
    let (storage_handle, version_handle) = match plan {
        CatalogPlanV1::CreateWorkspace { .. } => (None, None),
        CatalogPlanV1::Snapshot { source, .. }
        | CatalogPlanV1::SetQuota {
            dataset: source, ..
        }
        | CatalogPlanV1::DestroyDataset { dataset: source } => {
            (Some(source.storage_handle()), None)
        }
        CatalogPlanV1::HoldSnapshot { snapshot, .. }
        | CatalogPlanV1::ReleaseHold { snapshot, .. }
        | CatalogPlanV1::DestroySnapshot { snapshot } => (
            Some(snapshot.dataset().storage_handle()),
            Some(snapshot.version_handle()),
        ),
        CatalogPlanV1::Clone { source, .. } => (
            Some(source.dataset().storage_handle()),
            Some(source.version_handle()),
        ),
    };
    encoder.field(
        26,
        storage_handle.as_ref().map_or(&[], <[u8; 32]>::as_slice),
    )?;
    encoder.field(
        27,
        version_handle.as_ref().map_or(&[], <[u8; 32]>::as_slice),
    )
}

fn encode_space(
    encoder: &mut Encoder,
    space: Option<WorkspaceSpacePolicyV1>,
    ancestor: Option<&ProjectAncestorPolicyV1>,
) -> Result<(), CatalogSemanticError> {
    let (Some(space), Some(ancestor)) = (space, ancestor) else {
        for tag in 16..=22 {
            encoder.field(tag, &[])?;
        }
        return Ok(());
    };
    encoder.field(16, &space.refquota_bytes.to_be_bytes())?;
    match space.reservation {
        ReservationPolicy::None => encoder.field(17, &[0])?,
        ReservationPolicy::Exact(bytes) => {
            let mut value = Vec::with_capacity(9);
            value.push(1);
            value.extend_from_slice(&bytes.to_be_bytes());
            encoder.field(17, &value)?;
        }
    }
    encoder.field(18, ancestor.dataset.name().as_bytes())?;
    encoder.field(19, &ancestor.dataset.guid().to_be_bytes())?;
    encoder.field(20, &ancestor.quota_bytes.to_be_bytes())?;
    encoder.field(21, &ancestor.filesystem_limit.to_be_bytes())?;
    encoder.field(22, &ancestor.snapshot_limit.to_be_bytes())
}

fn encode_postcondition(
    encoder: &mut Encoder,
    postcondition: &PostconditionPolicyV1,
) -> Result<(), CatalogSemanticError> {
    let (mode, kind, name, guid, space, hold, present, origin_name, origin_guid) =
        match postcondition {
            PostconditionPolicyV1::CaptureDataset {
                name,
                space,
                origin_name,
                origin_guid,
                origin_hold,
            } => (
                1,
                CatalogObjectKind::Dataset,
                name.as_str(),
                0,
                Some(*space),
                *origin_hold,
                false,
                origin_name.as_deref(),
                *origin_guid,
            ),
            PostconditionPolicyV1::CaptureSnapshot { name, source_guid } => (
                2,
                CatalogObjectKind::Snapshot,
                name.as_str(),
                0,
                None,
                None,
                false,
                None,
                *source_guid,
            ),
            PostconditionPolicyV1::HoldState {
                name,
                guid,
                hold_id,
                present,
            } => (
                3,
                CatalogObjectKind::Snapshot,
                name.as_str(),
                *guid,
                None,
                Some(*hold_id),
                *present,
                None,
                0,
            ),
            PostconditionPolicyV1::DatasetProperties { name, guid, space } => (
                4,
                CatalogObjectKind::Dataset,
                name.as_str(),
                *guid,
                Some(*space),
                None,
                false,
                None,
                0,
            ),
            PostconditionPolicyV1::Absent { name, kind, guid } => {
                (5, *kind, name.as_str(), *guid, None, None, false, None, 0)
            }
        };
    encoder.field(28, &[mode])?;
    encoder.field(
        29,
        &[match kind {
            CatalogObjectKind::Dataset => 1,
            CatalogObjectKind::Snapshot => 2,
        }],
    )?;
    encoder.field(30, &guid.to_be_bytes())?;
    encoder.field(31, name.as_bytes())?;
    encoder.field(32, &origin_guid.to_be_bytes())?;
    encoder.field(33, origin_name.unwrap_or_default().as_bytes())?;
    encoder.field(
        34,
        hold.map(HoldId::as_bytes)
            .as_ref()
            .map_or(&[], <[u8; 16]>::as_slice),
    )?;
    encoder.field(35, &[u8::from(present)])?;
    match space {
        None => {
            encoder.field(36, &[])?;
            encoder.field(37, &[])
        }
        Some(space) => {
            encoder.field(36, &space.refquota_bytes().to_be_bytes())?;
            match space.reservation() {
                ReservationPolicy::None => encoder.field(37, &[0]),
                ReservationPolicy::Exact(bytes) => {
                    let mut value = Vec::with_capacity(9);
                    value.push(1);
                    value.extend_from_slice(&bytes.to_be_bytes());
                    encoder.field(37, &value)
                }
            }
        }
    }
}

fn validate_descendant(root: &ManagedDatasetRoot, name: &str) -> Result<(), CatalogSemanticError> {
    let prefix = format!("{}/", root.dataset_prefix);
    if !valid_dataset_name(name) || !name.starts_with(&prefix) {
        Err(CatalogSemanticError::InvalidName)
    } else {
        Ok(())
    }
}

fn validate_snapshot_component(dataset: &str, component: &str) -> Result<(), CatalogSemanticError> {
    let length = dataset
        .len()
        .checked_add(1)
        .and_then(|value| value.checked_add(component.len()));
    if !valid_component(component) || length.is_none_or(|value| value > MAXIMUM_NAME_BYTES) {
        Err(CatalogSemanticError::InvalidName)
    } else {
        Ok(())
    }
}

fn valid_dataset_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAXIMUM_NAME_BYTES
        && !name.contains(['@', '#', '\0'])
        && name.split('/').all(valid_component)
}

fn valid_component(component: &str) -> bool {
    !component.is_empty()
        && component != "."
        && component != ".."
        && !component.starts_with('-')
        && component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(768),
        }
    }

    fn field(&mut self, tag: u8, value: &[u8]) -> Result<(), CatalogSemanticError> {
        let length =
            u32::try_from(value.len()).map_err(|_| CatalogSemanticError::EncodingTooLarge)?;
        let next = self
            .bytes
            .len()
            .checked_add(5)
            .and_then(|size| size.checked_add(value.len()))
            .filter(|size| *size <= MAXIMUM_CANONICAL_BYTES)
            .ok_or(CatalogSemanticError::EncodingTooLarge)?;
        self.bytes.reserve(next - self.bytes.len());
        self.bytes.push(tag);
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn root() -> ManagedDatasetRoot {
        ManagedDatasetRoot::from_catalog("tank", "tank/aos", 10).unwrap()
    }

    fn domains() -> StorageDomainsV1 {
        StorageDomainsV1::new(
            ObjectDigest::from_bytes([21; 32]),
            ObjectDigest::from_bytes([22; 32]),
            ObjectDigest::from_bytes([23; 32]),
            ObjectDigest::from_bytes([24; 32]),
        )
        .unwrap()
    }

    fn space() -> WorkspaceSpacePolicyV1 {
        WorkspaceSpacePolicyV1::new(4096, ReservationPolicy::Exact(1024)).unwrap()
    }

    fn ancestor() -> ProjectAncestorPolicyV1 {
        let dataset =
            ResolvedDataset::from_catalog(root(), "tank/aos/project", 15, [1; 32], domains())
                .unwrap();
        ProjectAncestorPolicyV1::new(dataset, 65_536, 8, 16).unwrap()
    }

    #[test]
    fn resolved_objects_require_managed_descendants_and_nonzero_guids() {
        assert!(ManagedDatasetRoot::from_catalog("tank", "other/aos", 1).is_err());
        assert!(ManagedDatasetRoot::from_catalog("tank", "tank", 1).is_err());
        assert!(ManagedDatasetRoot::from_catalog("tank", "tank/aos", 0).is_err());
        assert!(ResolvedDataset::from_catalog(root(), "tank/aos", 11, [1; 32], domains()).is_err());
        assert!(
            ResolvedDataset::from_catalog(root(), "tank/else/work", 11, [1; 32], domains())
                .is_err()
        );
        assert!(
            ResolvedDataset::from_catalog(root(), "tank/aos/-r", 11, [1; 32], domains()).is_err()
        );
        assert!(
            ResolvedDataset::from_catalog(root(), "tank/aos/work", 0, [1; 32], domains()).is_err()
        );
        assert!(
            ResolvedDataset::from_catalog(root(), "tank/aos/work", 11, [0; 32], domains()).is_err()
        );

        let dataset =
            ResolvedDataset::from_catalog(root(), "tank/aos/work", 11, [1; 32], domains()).unwrap();
        assert!(ResolvedSnapshot::from_catalog(dataset.clone(), "-r", 12, [2; 32]).is_err());
        assert!(ResolvedSnapshot::from_catalog(dataset.clone(), "version", 0, [2; 32]).is_err());
        assert!(ResolvedSnapshot::from_catalog(dataset.clone(), "version", 12, [0; 32]).is_err());
        assert_eq!(
            ResolvedSnapshot::from_catalog(dataset, "version", 12, [2; 32])
                .unwrap()
                .name(),
            "tank/aos/work@version"
        );
    }

    #[test]
    fn catalog_digest_binds_identity_policy_domains_and_generation() {
        let destination =
            PlannedDataset::from_catalog(root(), "tank/aos/project/new", domains()).unwrap();
        let baseline = ResolvedCatalogCommitmentV1::new(
            7,
            domains(),
            CatalogPlanV1::CreateWorkspace {
                destination: destination.clone(),
                space: space(),
                ancestor: ancestor(),
            },
        )
        .unwrap();
        let changed_generation = ResolvedCatalogCommitmentV1::new(
            8,
            domains(),
            CatalogPlanV1::CreateWorkspace {
                destination: destination.clone(),
                space: space(),
                ancestor: ancestor(),
            },
        )
        .unwrap();
        let changed_policy = ResolvedCatalogCommitmentV1::new(
            7,
            domains(),
            CatalogPlanV1::CreateWorkspace {
                destination,
                space: WorkspaceSpacePolicyV1::new(4097, ReservationPolicy::Exact(1024)).unwrap(),
                ancestor: ancestor(),
            },
        )
        .unwrap();
        let changed_ancestor = ResolvedCatalogCommitmentV1::new(
            7,
            domains(),
            CatalogPlanV1::CreateWorkspace {
                destination: PlannedDataset::from_catalog(
                    root(),
                    "tank/aos/project/new",
                    domains(),
                )
                .unwrap(),
                space: space(),
                ancestor: ProjectAncestorPolicyV1::new(
                    ResolvedDataset::from_catalog(
                        root(),
                        "tank/aos/project",
                        16,
                        [1; 32],
                        domains(),
                    )
                    .unwrap(),
                    65_536,
                    8,
                    16,
                )
                .unwrap(),
            },
        )
        .unwrap();
        assert_ne!(baseline.digest(), changed_generation.digest());
        assert_ne!(baseline.digest(), changed_policy.digest());
        assert_ne!(baseline.digest(), changed_ancestor.digest());
        assert_eq!(
            baseline.digest().as_bytes(),
            &[
                61, 44, 81, 98, 56, 242, 203, 70, 139, 233, 9, 63, 193, 90, 59, 94, 9, 248, 228,
                134, 241, 195, 239, 31, 68, 193, 61, 151, 204, 176, 21, 113,
            ]
        );
        assert_eq!(baseline.binding().generation(), 7);
        assert_eq!(baseline.binding().digest(), baseline.digest());
        assert!(
            baseline
                .canonical_bytes()
                .windows(8)
                .any(|value| value == b"tank/aos")
        );
    }

    #[test]
    fn clone_requires_one_root_and_binds_origin_hold() {
        let dataset =
            ResolvedDataset::from_catalog(root(), "tank/aos/source", 11, [1; 32], domains())
                .unwrap();
        let snapshot = ResolvedSnapshot::from_catalog(dataset, "v1", 12, [2; 32]).unwrap();
        let other_root = ManagedDatasetRoot::from_catalog("other", "other/aos", 13).unwrap();
        let destination =
            PlannedDataset::from_catalog(other_root.clone(), "other/aos/project/clone", domains())
                .unwrap();
        let plan = CatalogPlanV1::Clone {
            source: Box::new(snapshot),
            origin_hold: ActiveHoldEvidence::from_catalog(
                12,
                HoldId::from_bytes([31; 16]).unwrap(),
            )
            .unwrap(),
            destination,
            space: space(),
            ancestor: ProjectAncestorPolicyV1::new(
                ResolvedDataset::from_catalog(
                    other_root,
                    "other/aos/project",
                    15,
                    [3; 32],
                    domains(),
                )
                .unwrap(),
                65_536,
                8,
                16,
            )
            .unwrap(),
        };
        assert_eq!(
            ResolvedCatalogCommitmentV1::new(1, domains(), plan),
            Err(CatalogSemanticError::InconsistentPlan)
        );
        assert!(HoldId::from_bytes([0; 16]).is_err());
    }

    #[test]
    fn accounting_policy_is_finite_and_explicit() {
        assert!(WorkspaceSpacePolicyV1::new(0, ReservationPolicy::None).is_err());
        assert!(WorkspaceSpacePolicyV1::new(100, ReservationPolicy::Exact(101)).is_err());
        let dataset =
            ResolvedDataset::from_catalog(root(), "tank/aos/project", 15, [1; 32], domains())
                .unwrap();
        assert!(ProjectAncestorPolicyV1::new(dataset, 0, 1, 1).is_err());

        let sibling =
            ResolvedDataset::from_catalog(root(), "tank/aos/sibling", 16, [1; 32], domains())
                .unwrap();
        let plan = CatalogPlanV1::CreateWorkspace {
            destination: PlannedDataset::from_catalog(root(), "tank/aos/project/new", domains())
                .unwrap(),
            space: space(),
            ancestor: ProjectAncestorPolicyV1::new(sibling, 65_536, 8, 16).unwrap(),
        };
        assert_eq!(
            ResolvedCatalogCommitmentV1::new(1, domains(), plan),
            Err(CatalogSemanticError::InconsistentPlan)
        );

        let too_small = ProjectAncestorPolicyV1::new(
            ResolvedDataset::from_catalog(root(), "tank/aos/project", 15, [9; 32], domains())
                .unwrap(),
            4095,
            8,
            16,
        )
        .unwrap();
        let plan = CatalogPlanV1::CreateWorkspace {
            destination: PlannedDataset::from_catalog(root(), "tank/aos/project/new", domains())
                .unwrap(),
            space: space(),
            ancestor: too_small,
        };
        assert_eq!(
            ResolvedCatalogCommitmentV1::new(1, domains(), plan),
            Err(CatalogSemanticError::InconsistentPlan)
        );
    }

    #[test]
    fn clone_rejects_domain_and_active_hold_substitution() {
        let source_dataset = ResolvedDataset::from_catalog(
            root(),
            "tank/aos/project/source",
            11,
            [1; 32],
            domains(),
        )
        .unwrap();
        let source = ResolvedSnapshot::from_catalog(source_dataset, "v1", 12, [2; 32]).unwrap();
        let incompatible = StorageDomainsV1::new(
            ObjectDigest::from_bytes([99; 32]),
            ObjectDigest::from_bytes([22; 32]),
            ObjectDigest::from_bytes([23; 32]),
            ObjectDigest::from_bytes([24; 32]),
        )
        .unwrap();
        let plan = CatalogPlanV1::Clone {
            source: Box::new(source.clone()),
            origin_hold: ActiveHoldEvidence::from_catalog(
                source.guid(),
                HoldId::from_bytes([31; 16]).unwrap(),
            )
            .unwrap(),
            destination: PlannedDataset::from_catalog(
                root(),
                "tank/aos/project/clone",
                incompatible,
            )
            .unwrap(),
            space: space(),
            ancestor: ancestor(),
        };
        assert_eq!(
            ResolvedCatalogCommitmentV1::new(1, incompatible, plan),
            Err(CatalogSemanticError::InconsistentPlan)
        );

        let plan = CatalogPlanV1::Clone {
            source: Box::new(source),
            origin_hold: ActiveHoldEvidence::from_catalog(
                13,
                HoldId::from_bytes([31; 16]).unwrap(),
            )
            .unwrap(),
            destination: PlannedDataset::from_catalog(root(), "tank/aos/project/clone", domains())
                .unwrap(),
            space: space(),
            ancestor: ancestor(),
        };
        assert_eq!(
            ResolvedCatalogCommitmentV1::new(1, domains(), plan),
            Err(CatalogSemanticError::InconsistentPlan)
        );
    }
}
