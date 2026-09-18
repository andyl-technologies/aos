//! Assignment-bound descriptor catalog for mount resources.
//!
//! An authenticated provider supplies a live source only while CREATE clones
//! it. During Host-backed preparation, Mount verifies that source, the retained
//! Host root and namespaces, and its broker-owned destination slot, then
//! atomically publishes `catalog.json`. The durable entry retains complete
//! source-realization evidence but no source path. Existing-resource actions
//! reconstruct their exact destination authority without consulting the
//! provider; callers never supply a host path or descriptor.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use aos_proto::aos::sandbox::local::v1::MountAction;
use aos_proto::aos::sandbox::local::v1::MountSourceConsistency;
use aos_sandbox_core::{
    DecodeLimits, ObjectDescriptor, ObjectDigest, decode_view_source, encode_view_source,
};
use aos_sandbox_linux::inventory::{MountId, MountListOrder, MountNamespace, MountObservation};
use aos_sandbox_linux::path::{BeneathRoot, FileIdentity, ResolveOptions, ResolvedPath};
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceIdentity};
use aos_sandbox_protocol::{
    SourceRealizationBindingV1, ValidatedAssignmentFence, ValidatedMountRequest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::authorization::semantics_v1::MountCatalogCommitmentV1;
use crate::destination_slot::{
    anchor_catalog_relative_path, catalog_relative_path as destination_slot_catalog_path,
    payload_anchor_relative_path, payload_slot_relative_path,
};
use crate::host_scope::ObservedMountScope;
#[cfg(all(test, feature = "kernel-tests"))]
use crate::source_pin::FixtureSourcePins;
use crate::source_pin::{
    ReopenedSourcePins, ResolvedSourcePin, SourcePinProofClassV1, SourcePinResolver,
    SourcePinRowV1Ext, SourceRealizationEvidenceV1, UnavailableSourcePins,
};
use crate::{MountError, Result};

const CATALOG_FILE: &str = "catalog.json";
const CATALOG_NEXT_FILE: &str = "catalog.next";
const MAXIMUM_CATALOG_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_ENTRIES: usize = 16_384;
const MAXIMUM_RELATIVE_PATH_BYTES: usize = 4096;
const MAXIMUM_PREPARED_NAMESPACES: usize = 1_024;
const MAXIMUM_TOPOLOGY_MOUNTS: usize = 65_536;
const PREPARED_COMMITMENT_VERSION: u16 = 2;
const REQUIRED_ATTACHMENT_ANCHOR_ATTRIBUTES: u64 = 0x0000_000f;
const RUN_RELATIVE_PATH: &str = "run";
const RUN_AOS_RELATIVE_PATH: &str = "run/aos";
const ROOT_MOUNT_POINT: &[u8] = b"/";
const RUN_MOUNT_POINT: &[u8] = b"/run";
const RUN_AOS_MOUNT_POINT: &[u8] = b"/run/aos";
const ATTACHMENT_ANCHOR_MOUNT_POINT: &[u8] = b"/run/aos/attachments";

/// Contains the descriptors pinned for one exact mount operation generation.
#[derive(Debug)]
pub struct ResolvedMountResources {
    /// Pinned source directory present only for CREATE cloning.
    pub source: Option<ResolvedPath>,
    /// Durable source identity used by non-CREATE helper plans.
    pub(crate) source_identity: FileIdentity,
    /// Exact journal-correlatable identity of the authenticated source.
    pub(crate) source_realization: SourceRealizationEvidenceV1,
    /// Pinned payload mount namespace used only by the helper.
    pub mount_namespace: NamespaceFd,
    /// Pinned payload user namespace used for the mount idmap.
    pub user_namespace: NamespaceFd,
    /// Pinned payload root used for helper path hygiene and verification.
    pub target_root: ResolvedPath,
    /// Pinned broker-owned destination slot.
    pub target_slot: ResolvedPath,
    /// Pinned payload attachment anchor used for all slot resolution.
    pub attachment_anchor: BeneathRoot,
    /// Exact verified mount-tree and idmap facts delegated to the helper.
    pub(crate) topology: ResolvedMountTopology,
    /// Non-circular commitment to the exact verified catalog behavior facts.
    pub(crate) authorization_commitment: MountCatalogCommitmentV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedMountTopology {
    pub(crate) protected_anchor_mount_id: u64,
    pub(crate) target_root_mount_id: u64,
    pub(crate) run_mount_id: u64,
    pub(crate) attachment_anchor_mount_id: u64,
    pub(crate) target_mount_namespace_id: u64,
    pub(crate) attachment_anchor_mount_attributes: u64,
    pub(crate) attachment_anchor_idmap_digest: [u8; 32],
}

/// Resolves one validated semantic request into exact pinned kernel objects.
pub trait MountCatalog {
    /// Reports whether durable-resource actions can run without source acquisition.
    #[must_use]
    fn supports_existing_resource_actions(&self) -> bool {
        false
    }

    /// Reports whether preparation can currently publish executable authority.
    #[must_use]
    fn supports_catalog_preparation(&self) -> bool {
        false
    }

    /// Resolves and verifies all resources from one atomic catalog snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown, stale, mismatched, replaced, incorrectly
    /// typed or path-unsafe catalog resources.
    fn resolve(
        &self,
        request: &ValidatedMountRequest,
        expected_source: Option<SourceRealizationEvidenceV1>,
    ) -> Result<ResolvedMountResources>;

    /// Retains one authenticated Host scope and resolves its catalog commitment.
    ///
    /// The default rejects preparation for catalogs that deliberately use only
    /// static test pins.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported preparation or an invalid, conflicting,
    /// expired, or unresolvable Host scope.
    fn prepare(
        &mut self,
        _request: &ValidatedMountRequest,
        _scope: ObservedMountScope,
        _expected_source: Option<SourceRealizationEvidenceV1>,
    ) -> Result<ObjectDigest> {
        Err(MountError::Worker(
            "mount catalog does not accept Host scope preparation".to_owned(),
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PreparedNamespaceKey {
    sandbox_id: [u8; 16],
    incarnation_id: [u8; 16],
    namespace_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreparedScopeBinding {
    runtime_handle: [u8; 32],
    payload_scope_handle: [u8; 32],
    root: FileIdentity,
    mount_namespace: NamespaceIdentity,
    user_namespace: NamespaceIdentity,
}

struct PreparedNamespace {
    binding: PreparedScopeBinding,
    scope: ObservedMountScope,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogAssignment {
    sandbox_id: [u8; 16],
    incarnation_id: [u8; 16],
    assignment_epoch: u64,
    desired_generation: u64,
    assignment_digest: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MountCatalogEntry {
    assignment: CatalogAssignment,
    attachment_id: [u8; 16],
    destination_slot_id: [u8; 16],
    view_revision: ObjectDescriptor,
    source_generation: u64,
    namespace_generation: u64,
    desired_attachment_generation: u64,
    resource_attachment_generation: u64,
    source_view_id: [u8; 16],
    source_incarnation_id: Option<[u8; 16]>,
    source_consistency: CatalogSourceConsistency,
    source_handle: Vec<u8>,
    source_binding_digest: [u8; 32],
    attachment_lease_id: [u8; 16],
    attachment_lease_issued_seconds: i64,
    attachment_lease_expires_seconds: i64,
    source_realization_handle: [u8; 32],
    source_physical_proof_digest: [u8; 32],
    source_unique_mount_id: u64,
    source_provider_authority_digest: [u8; 32],
    source_provider_authority_id: [u8; 16],
    source_provider_authority_generation: u64,
    source_provider_resource_id: [u8; 32],
    source_provider_resource_generation: u64,
    source_provider_resource_digest: [u8; 32],
    source_provider_catalog_generation: u64,
    source_provider_catalog_digest: [u8; 32],
    source_kernel_boot_id: [u8; 16],
    source_proof_class: SourcePinProofClassV1,
    mount_namespace_path: String,
    user_namespace_path: String,
    target_root_path: String,
    target_slot_path: String,
    target_relative_path: String,
    prepared_scope: bool,
    commitment_version: u16,
    runtime_handle: [u8; 32],
    payload_scope_handle: [u8; 32],
    source_identity: FileIdentityWire,
    mount_namespace_identity: NamespaceIdentityWire,
    user_namespace_identity: NamespaceIdentityWire,
    target_root_identity: FileIdentityWire,
    target_slot_identity: FileIdentityWire,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CatalogSourceConsistency {
    ImmutableRevision,
    LocalLive,
    BestEffortReplica,
}

impl CatalogSourceConsistency {
    fn from_protocol(value: MountSourceConsistency) -> Result<Self> {
        match value {
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION => {
                Ok(Self::ImmutableRevision)
            }
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE => Ok(Self::LocalLive),
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA => {
                Ok(Self::BestEffortReplica)
            }
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_UNSPECIFIED
            | MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_TRANSACTIONAL_SERVICE => Err(
                MountError::State("validated mount source consistency is not native".to_owned()),
            ),
        }
    }

    const fn protocol_value(self) -> MountSourceConsistency {
        match self {
            Self::ImmutableRevision => {
                MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION
            }
            Self::LocalLive => MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE,
            Self::BestEffortReplica => {
                MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA
            }
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::ImmutableRevision => 1,
            Self::LocalLive => 2,
            Self::BestEffortReplica => 4,
        }
    }
}

impl CatalogAssignment {
    fn from_request(request: &ValidatedMountRequest) -> Self {
        Self {
            sandbox_id: *request.fence().sandbox_id(),
            incarnation_id: *request.fence().incarnation_id(),
            assignment_epoch: request.fence().assignment_epoch(),
            desired_generation: request.fence().desired_generation(),
            assignment_digest: *request.fence().assignment_digest(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FileIdentityWire {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NamespaceIdentityWire {
    device: u64,
    inode: u64,
}

impl From<FileIdentity> for FileIdentityWire {
    fn from(value: FileIdentity) -> Self {
        Self {
            device: value.device,
            inode: value.inode,
        }
    }
}

impl From<NamespaceIdentity> for NamespaceIdentityWire {
    fn from(value: NamespaceIdentity) -> Self {
        Self {
            device: value.device,
            inode: value.inode,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MountCatalogSnapshot {
    generation: u64,
    entries: Vec<MountCatalogEntry>,
}

/// Reads an atomically published exact catalog beneath a private root.
#[derive(Debug)]
pub struct FileMountCatalog {
    root: BeneathRoot,
}

/// Combines the protected file catalog with short-lived Host scope custody.
///
/// One namespace generation can be refreshed only with the same exact Host
/// binding. A changed root, namespace, runtime, or payload-scope handle requires
/// a new signed namespace generation rather than silently replacing authority.
/// Every retained row carries the exact Host scope and source binding required
/// to resolve source-bound resources for a helper effect.
pub struct PreparedMountCatalog {
    catalog: FileMountCatalog,
    prepared: BTreeMap<PreparedNamespaceKey, PreparedNamespace>,
    source_pins: Box<dyn SourcePinResolver>,
}

impl PreparedMountCatalog {
    /// Constructs an empty bounded preparation registry over a protected catalog.
    #[must_use]
    pub fn new(catalog: FileMountCatalog) -> Self {
        Self {
            catalog,
            prepared: BTreeMap::new(),
            source_pins: Box::new(UnavailableSourcePins),
        }
    }

    /// Constructs a catalog over same-boot source custody authenticated at startup.
    #[must_use]
    pub fn with_reopened_sources(catalog: FileMountCatalog, sources: ReopenedSourcePins) -> Self {
        Self {
            catalog,
            prepared: BTreeMap::new(),
            source_pins: Box::new(sources),
        }
    }

    /// Constructs an exact authenticated source fixture for crate tests.
    #[cfg(all(test, feature = "kernel-tests"))]
    pub(crate) fn with_fixture_source(
        catalog: FileMountCatalog,
        binding: SourceRealizationBindingV1,
        source: ResolvedPath,
        kernel_boot_id: [u8; 16],
    ) -> Result<Self> {
        Ok(Self {
            catalog,
            prepared: BTreeMap::new(),
            source_pins: Box::new(FixtureSourcePins::new(binding, source, kernel_boot_id)?),
        })
    }
}

impl FileMountCatalog {
    /// Opens a root-owned catalog directory without following its final link.
    ///
    /// # Errors
    ///
    /// Returns an error unless the path is a real root-owned directory with no
    /// group or other permission bits.
    pub fn open_root_owned(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| MountError::State(error.to_string()))?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(MountError::State(
                "mount catalog root must be a private root-owned real directory".to_owned(),
            ));
        }
        let fd: OwnedFd = rustix::fs::open(
            path,
            rustix::fs::OFlags::PATH
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| MountError::State(error.to_string()))?;
        Ok(Self {
            root: BeneathRoot::from_owned(fd)
                .map_err(|error| MountError::State(error.to_string()))?,
        })
    }

    fn snapshot(&self) -> Result<MountCatalogSnapshot> {
        let bytes = self
            .root
            .open_regular(Path::new(CATALOG_FILE))
            .and_then(|file| file.read_bounded(MAXIMUM_CATALOG_BYTES))
            .map_err(|error| MountError::State(error.to_string()))?;
        let snapshot: MountCatalogSnapshot =
            serde_json::from_slice(&bytes).map_err(|error| MountError::State(error.to_string()))?;
        snapshot.validate()?;
        Ok(snapshot)
    }
}

impl MountCatalog for PreparedMountCatalog {
    fn supports_existing_resource_actions(&self) -> bool {
        true
    }

    fn supports_catalog_preparation(&self) -> bool {
        true
    }

    fn resolve(
        &self,
        request: &ValidatedMountRequest,
        expected_source: Option<SourceRealizationEvidenceV1>,
    ) -> Result<ResolvedMountResources> {
        let prepared = self
            .prepared
            .get(&prepared_namespace_key(request))
            .ok_or_else(|| {
                MountError::Worker("mount namespace scope is not prepared".to_owned())
            })?;
        if prepared.scope.valid_until_boottime_nanoseconds() <= boottime_nanoseconds()? {
            return Err(MountError::Worker(
                "prepared mount namespace scope expired".to_owned(),
            ));
        }
        let source = if action_requires_live_source(request.action()) {
            let source_binding = self.catalog.source_binding_for_request(request)?;
            Some(self.source_pins.resolve(&source_binding)?)
        } else {
            None
        };
        self.catalog.inspect_prepared(
            request,
            &prepared.scope,
            prepared.binding,
            source,
            expected_source,
        )
    }

    fn prepare(
        &mut self,
        request: &ValidatedMountRequest,
        scope: ObservedMountScope,
        expected_source: Option<SourceRealizationEvidenceV1>,
    ) -> Result<ObjectDigest> {
        scope
            .recheck()
            .map_err(|error| MountError::Worker(error.to_string()))?;
        if scope.metadata().fence() != request.fence() {
            return Err(MountError::Fence(
                "Host scope assignment differs from Mount preparation",
            ));
        }

        let now = boottime_nanoseconds()?;
        self.prepared
            .retain(|_, prepared| prepared.scope.valid_until_boottime_nanoseconds() > now);
        let key = prepared_namespace_key(request);
        let binding = prepared_scope_binding(&scope);
        if let Some(current) = self.prepared.get(&key)
            && current.binding != binding
        {
            return Err(MountError::Fence(
                "namespace generation cannot replace its prepared Host scope",
            ));
        }
        if !self.prepared.contains_key(&key) && self.prepared.len() >= MAXIMUM_PREPARED_NAMESPACES {
            return Err(MountError::Worker(
                "prepared mount namespace registry is full".to_owned(),
            ));
        }

        let source = if action_requires_live_source(request.action()) {
            let source_binding = self.catalog.source_binding_for_request(request)?;
            Some(self.source_pins.resolve(&source_binding)?)
        } else {
            None
        };
        if let Some(source) = &source {
            require_preparation_source_directory(source.source().identity())?;
        }
        let catalog_source = source
            .as_ref()
            .map(ResolvedSourcePin::evidence)
            .or(expected_source);
        let inspection = if self
            .catalog
            .contains_matching_entry(request, catalog_source)?
        {
            self.catalog
                .inspect_prepared(request, &scope, binding, source, catalog_source)?
        } else if let Some(source) = source {
            self.catalog
                .publish_prepared(request, &scope, binding, source)?
        } else {
            return Err(MountError::Worker(
                "existing-resource catalog realization is unavailable".to_owned(),
            ));
        };
        let commitment = inspection.authorization_commitment.digest();
        self.prepared
            .insert(key, PreparedNamespace { binding, scope });
        Ok(commitment)
    }
}

const fn action_requires_live_source(action: MountAction) -> bool {
    matches!(action, MountAction::MOUNT_ACTION_CREATE_DETACHED)
}

fn require_preparation_source_directory(identity: FileIdentity) -> Result<()> {
    if identity.file_type != aos_sandbox_linux::path::FileType::Directory {
        return Err(MountError::Worker(
            "mount catalog source realization is not a directory".to_owned(),
        ));
    }
    Ok(())
}

impl FileMountCatalog {
    fn contains_matching_entry(
        &self,
        request: &ValidatedMountRequest,
        expected_source: Option<SourceRealizationEvidenceV1>,
    ) -> Result<bool> {
        Ok(self
            .snapshot_or_empty()?
            .entries
            .iter()
            .any(|entry| entry.matches(request) && entry.matches_realization(expected_source)))
    }

    fn publish_prepared(
        &self,
        request: &ValidatedMountRequest,
        scope: &ObservedMountScope,
        binding: PreparedScopeBinding,
        source: ResolvedSourcePin,
    ) -> Result<ResolvedMountResources> {
        let mut snapshot = self.snapshot_or_empty()?;
        let entry = self.prepared_entry(request, scope, &snapshot, &source)?;
        if !snapshot.upsert(entry)? {
            return self.inspect_prepared(request, scope, binding, Some(source), None);
        }
        self.publish_snapshot(&snapshot)?;

        let published = self.snapshot()?;
        if published != snapshot {
            return Err(MountError::State(
                "mount catalog publication did not reproduce its exact snapshot".to_owned(),
            ));
        }
        self.inspect_prepared(request, scope, binding, Some(source), None)
    }

    fn snapshot_or_empty(&self) -> Result<MountCatalogSnapshot> {
        match self.read_snapshot_bytes() {
            Ok(bytes) => {
                let snapshot: MountCatalogSnapshot = serde_json::from_slice(&bytes)
                    .map_err(|error| MountError::State(error.to_string()))?;
                snapshot.validate()?;
                Ok(snapshot)
            }
            Err(error) if error == rustix::io::Errno::NOENT => Ok(MountCatalogSnapshot {
                generation: 0,
                entries: Vec::new(),
            }),
            Err(error) => Err(MountError::State(error.to_string())),
        }
    }

    fn read_snapshot_bytes(&self) -> std::result::Result<Vec<u8>, rustix::io::Errno> {
        let descriptor = rustix::fs::openat(
            self.root.as_fd(),
            CATALOG_FILE,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        let metadata = rustix::fs::fstat(&descriptor)?;
        if rustix::fs::FileType::from_raw_mode(metadata.st_mode)
            != rustix::fs::FileType::RegularFile
        {
            return Err(rustix::io::Errno::INVAL);
        }

        let mut file = std::fs::File::from(descriptor);
        let mut bytes = Vec::new();
        let maximum_read =
            u64::try_from(MAXIMUM_CATALOG_BYTES + 1).map_err(|_| rustix::io::Errno::OVERFLOW)?;
        std::io::Read::by_ref(&mut file)
            .take(maximum_read)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                rustix::io::Errno::from_io_error(&error).unwrap_or(rustix::io::Errno::IO)
            })?;
        if bytes.len() > MAXIMUM_CATALOG_BYTES {
            return Err(rustix::io::Errno::FBIG);
        }
        Ok(bytes)
    }

    fn prepared_entry(
        &self,
        request: &ValidatedMountRequest,
        scope: &ObservedMountScope,
        snapshot: &MountCatalogSnapshot,
        source_pin: &ResolvedSourcePin,
    ) -> Result<MountCatalogEntry> {
        let root_identity = FileIdentityWire::from(scope.root().identity());
        let mount_namespace_identity =
            NamespaceIdentityWire::from(scope.mount_namespace().identity());
        let user_namespace_identity =
            NamespaceIdentityWire::from(scope.user_namespace().identity());
        if snapshot.entries.iter().any(|entry| {
            entry.assignment.sandbox_id == *request.fence().sandbox_id()
                && entry.assignment.incarnation_id == *request.fence().incarnation_id()
                && entry.namespace_generation == request.namespace_generation()
                && (entry.target_root_identity != root_identity
                    || entry.mount_namespace_identity != mount_namespace_identity
                    || entry.user_namespace_identity != user_namespace_identity
                    || entry.runtime_handle != *scope.metadata().runtime_handle()
                    || entry.payload_scope_handle != *scope.metadata().payload_scope_handle())
        }) {
            return Err(MountError::Fence(
                "namespace generation cannot replace its catalogued Host scope",
            ));
        }

        let prior = snapshot.entries.iter().find(|entry| {
            entry.assignment.incarnation_id == *request.fence().incarnation_id()
                && entry.attachment_id == *request.attachment_id()
        });
        let view_revision = match request.view_revision() {
            Some(revision) => revision.clone(),
            None => {
                let prior = prior
                    .filter(|entry| entry.matches_source(request))
                    .ok_or_else(|| {
                        MountError::Worker(
                            "mount catalog cannot recover an omitted source recipe".to_owned(),
                        )
                    })?;
                prior.view_revision.clone()
            }
        };
        let source = source_pin.source();
        let source_realization = source_pin.evidence();
        let target_slot_path = destination_slot_catalog_path(
            request.fence().sandbox_id(),
            request.fence().incarnation_id(),
            request.namespace_generation(),
            request.destination_slot_id(),
        );
        let protected_anchor_path = anchor_catalog_relative_path(
            request.fence().sandbox_id(),
            request.fence().incarnation_id(),
            request.namespace_generation(),
        );
        let protected_anchor =
            resolve_protected_directory(&self.root, path_text(&protected_anchor_path)?)?;
        let pinned_target_slot =
            resolve_protected_directory(&self.root, path_text(&target_slot_path)?)?;
        let protected_anchor_mount_id =
            verify_protected_slot(&protected_anchor, &pinned_target_slot)?;
        let target_relative_path = payload_slot_relative_path(request.destination_slot_id());
        let attachment_anchor = resolve_payload_anchor(scope.root())?;
        verify_anchor_identity(&attachment_anchor, &protected_anchor)?;
        verify_distinct_source(
            source.identity(),
            pinned_target_slot.identity(),
            attachment_anchor.identity(),
        )?;
        observe_mount_topology(
            MountNamespace::pinned(scope.mount_namespace()).map_err(linux_worker_error)?,
            scope.root(),
            &attachment_anchor,
            protected_anchor_mount_id,
        )?;

        let entry = MountCatalogEntry {
            assignment: CatalogAssignment::from_request(request),
            attachment_id: *request.attachment_id(),
            destination_slot_id: *request.destination_slot_id(),
            view_revision,
            source_generation: request.source_generation(),
            namespace_generation: request.namespace_generation(),
            desired_attachment_generation: request.desired_attachment_generation(),
            resource_attachment_generation: request.resource_attachment_generation(),
            source_view_id: *request.source_view_id(),
            source_incarnation_id: request.source_incarnation_id().copied(),
            source_consistency: CatalogSourceConsistency::from_protocol(
                request.source_consistency(),
            )?,
            source_handle: encode_view_source(request.source_handle()),
            source_binding_digest: request
                .source_binding()
                .ok_or_else(|| {
                    MountError::State("prepared source lacks an exact binding".to_owned())
                })?
                .digest()
                .as_bytes()
                .to_owned(),
            attachment_lease_id: *request.attachment_lease_id(),
            attachment_lease_issued_seconds: request.attachment_lease_issued_seconds(),
            attachment_lease_expires_seconds: request.attachment_lease_expires_seconds(),
            source_realization_handle: source_realization.handle,
            source_physical_proof_digest: source_realization.physical_proof_digest,
            source_unique_mount_id: source_realization.unique_mount_id,
            source_provider_authority_digest: source_realization.provider_authority_digest,
            source_provider_authority_id: source_realization.provider_authority_id,
            source_provider_authority_generation: source_realization.provider_authority_generation,
            source_provider_resource_id: source_realization.provider_resource_id,
            source_provider_resource_generation: source_realization.provider_resource_generation,
            source_provider_resource_digest: source_realization.provider_resource_digest,
            source_provider_catalog_generation: source_realization.provider_catalog_generation,
            source_provider_catalog_digest: source_realization.provider_catalog_digest,
            source_kernel_boot_id: source_realization.kernel_boot_id,
            source_proof_class: source_realization.proof_class,
            mount_namespace_path: String::new(),
            user_namespace_path: String::new(),
            target_root_path: String::new(),
            target_slot_path: path_text(&target_slot_path)?.to_owned(),
            target_relative_path: path_text(&target_relative_path)?.to_owned(),
            prepared_scope: true,
            commitment_version: PREPARED_COMMITMENT_VERSION,
            runtime_handle: *scope.metadata().runtime_handle(),
            payload_scope_handle: *scope.metadata().payload_scope_handle(),
            source_identity: FileIdentityWire::from(source.identity()),
            mount_namespace_identity,
            user_namespace_identity,
            target_root_identity: root_identity,
            target_slot_identity: FileIdentityWire::from(pinned_target_slot.identity()),
        };
        entry.validate()?;
        Ok(entry)
    }

    fn publish_snapshot(&self, snapshot: &MountCatalogSnapshot) -> Result<()> {
        snapshot.validate()?;
        let bytes =
            serde_json::to_vec(snapshot).map_err(|error| MountError::State(error.to_string()))?;
        if bytes.len() > MAXIMUM_CATALOG_BYTES {
            return Err(MountError::State(
                "encoded mount catalog exceeds sixteen MiB".to_owned(),
            ));
        }

        match rustix::fs::unlinkat(
            self.root.as_fd(),
            CATALOG_NEXT_FILE,
            rustix::fs::AtFlags::empty(),
        ) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(MountError::State(error.to_string())),
        }
        let descriptor = rustix::fs::openat(
            self.root.as_fd(),
            CATALOG_NEXT_FILE,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(|error| MountError::State(error.to_string()))?;
        let mut file = std::fs::File::from(descriptor);
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| MountError::State(error.to_string()))?;
        drop(file);

        rustix::fs::renameat(
            self.root.as_fd(),
            CATALOG_NEXT_FILE,
            self.root.as_fd(),
            CATALOG_FILE,
        )
        .map_err(|error| MountError::State(error.to_string()))?;
        sync_directory(&self.root)
    }

    fn matching_entry(
        &self,
        request: &ValidatedMountRequest,
        expected_source: Option<SourceRealizationEvidenceV1>,
    ) -> Result<(u64, MountCatalogEntry)> {
        let snapshot = self.snapshot()?;
        let mut matching = snapshot
            .entries
            .iter()
            .filter(|entry| entry.matches(request) && entry.matches_realization(expected_source));
        let entry = matching
            .next()
            .cloned()
            .ok_or_else(|| MountError::Worker("mount catalog tuple is unavailable".to_owned()))?;
        if matching.next().is_some() {
            return Err(MountError::State(
                "mount catalog tuple has ambiguous physical realizations".to_owned(),
            ));
        }
        Ok((snapshot.generation, entry))
    }

    fn source_binding_for_request(
        &self,
        request: &ValidatedMountRequest,
    ) -> Result<SourceRealizationBindingV1> {
        match request.source_binding() {
            Some(binding) => Ok(binding.clone()),
            None => self.matching_entry(request, None)?.1.source_binding(),
        }
    }

    /// Revalidates prepared facts and computes the entry's native commitment.
    fn inspect_prepared(
        &self,
        request: &ValidatedMountRequest,
        scope: &ObservedMountScope,
        binding: PreparedScopeBinding,
        source_pin: Option<ResolvedSourcePin>,
        expected_source: Option<SourceRealizationEvidenceV1>,
    ) -> Result<ResolvedMountResources> {
        let catalog_source = source_pin
            .as_ref()
            .map(ResolvedSourcePin::evidence)
            .or(expected_source);
        let (generation, entry) = self.matching_entry(request, catalog_source)?;
        if !entry.prepared_scope {
            return Err(MountError::Worker(
                "mount catalog entry lacks retained Host scope authority".to_owned(),
            ));
        }
        if entry.runtime_handle != binding.runtime_handle
            || entry.payload_scope_handle != binding.payload_scope_handle
        {
            return Err(MountError::Fence(
                "catalogued Host scope handles changed under one namespace generation",
            ));
        }
        let source_realization = entry.source_realization();
        let source = source_pin
            .map(|pin| {
                if pin.evidence() != source_realization {
                    return Err(MountError::Worker(
                        "current source realization differs from the prepared catalog".to_owned(),
                    ));
                }
                let source = pin.into_source();
                verify_file(source.identity(), entry.source_identity, "source")?;
                Ok(source)
            })
            .transpose()?;

        let (target_root, mount_namespace, user_namespace) = scope
            .duplicate_resources()
            .map_err(|error| MountError::Worker(error.to_string()))?;
        verify_file(
            target_root.identity(),
            entry.target_root_identity,
            "target root",
        )?;
        verify_namespace(
            mount_namespace.identity(),
            entry.mount_namespace_identity,
            "mount namespace",
        )?;
        verify_namespace(
            user_namespace.identity(),
            entry.user_namespace_identity,
            "user namespace",
        )?;

        let protected_anchor_path = anchor_catalog_relative_path(
            &entry.assignment.sandbox_id,
            &entry.assignment.incarnation_id,
            entry.namespace_generation,
        );
        let protected_anchor =
            resolve_protected_directory(&self.root, path_text(&protected_anchor_path)?)?;
        let pinned_target_slot = resolve_protected_directory(&self.root, &entry.target_slot_path)?;
        verify_file(
            pinned_target_slot.identity(),
            entry.target_slot_identity,
            "target slot pin",
        )?;
        let protected_anchor_mount_id =
            verify_protected_slot(&protected_anchor, &pinned_target_slot)?;
        let attachment_anchor = resolve_payload_anchor(scope.root())?;
        verify_anchor_identity(&attachment_anchor, &protected_anchor)?;
        if let Some(source) = &source {
            verify_distinct_source(
                source.identity(),
                pinned_target_slot.identity(),
                attachment_anchor.identity(),
            )?;
        }
        let topology = observe_mount_topology(
            MountNamespace::pinned(&mount_namespace).map_err(linux_worker_error)?,
            scope.root(),
            &attachment_anchor,
            protected_anchor_mount_id,
        )?;

        let authorization_commitment = prepared_catalog_authorization_commitment(
            generation,
            &entry,
            binding,
            FileIdentity {
                device: entry.source_identity.device,
                inode: entry.source_identity.inode,
                file_type: aos_sandbox_linux::path::FileType::Directory,
            },
            pinned_target_slot.identity(),
            topology,
            attachment_anchor.identity(),
        )?;
        Ok(ResolvedMountResources {
            source,
            source_identity: FileIdentity {
                device: entry.source_identity.device,
                inode: entry.source_identity.inode,
                file_type: aos_sandbox_linux::path::FileType::Directory,
            },
            source_realization,
            mount_namespace,
            user_namespace,
            target_root,
            target_slot: pinned_target_slot,
            attachment_anchor,
            topology,
            authorization_commitment,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn prepared_catalog_authorization_commitment(
    generation: u64,
    entry: &MountCatalogEntry,
    binding: PreparedScopeBinding,
    source: FileIdentity,
    target_slot: FileIdentity,
    topology: ResolvedMountTopology,
    attachment_anchor: FileIdentity,
) -> Result<MountCatalogCommitmentV1> {
    let mut host_binding = Vec::with_capacity(64);
    host_binding.extend_from_slice(&binding.runtime_handle);
    host_binding.extend_from_slice(&binding.payload_scope_handle);
    let mut bytes = catalog_authorization_bytes(
        generation,
        entry,
        &host_binding,
        source,
        binding.mount_namespace,
        binding.user_namespace,
        binding.root,
        target_slot,
    )?;
    append_prepared_topology(&mut bytes, topology, attachment_anchor);

    MountCatalogCommitmentV1::for_verified_canonical_bytes(&bytes)
        .map_err(|error| MountError::State(error.to_string()))
}

fn append_prepared_topology(
    bytes: &mut Vec<u8>,
    topology: ResolvedMountTopology,
    attachment_anchor: FileIdentity,
) {
    bytes.extend_from_slice(&attachment_anchor.device.to_be_bytes());
    bytes.extend_from_slice(&attachment_anchor.inode.to_be_bytes());
    for value in [
        topology.protected_anchor_mount_id,
        topology.target_root_mount_id,
        topology.run_mount_id,
        topology.attachment_anchor_mount_id,
        topology.target_mount_namespace_id,
        topology.attachment_anchor_mount_attributes,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&topology.attachment_anchor_idmap_digest);
}

#[allow(clippy::too_many_arguments)]
fn catalog_authorization_bytes(
    generation: u64,
    entry: &MountCatalogEntry,
    extra_binding: &[u8],
    source: FileIdentity,
    mount_namespace: NamespaceIdentity,
    user_namespace: NamespaceIdentity,
    target_root: FileIdentity,
    target_slot: FileIdentity,
) -> Result<Vec<u8>> {
    let media_type = entry.view_revision.media_type().as_str().as_bytes();
    let relative_path = entry.target_relative_path.as_bytes();
    let media_length = u16::try_from(media_type.len())
        .map_err(|_| MountError::State("catalog media type exceeds u16".to_owned()))?;
    let path_length = u32::try_from(relative_path.len())
        .map_err(|_| MountError::State("catalog relative path exceeds u32".to_owned()))?;
    let mut bytes = Vec::with_capacity(320 + media_type.len() + relative_path.len());
    bytes.extend_from_slice(b"AOSMCAT2");
    bytes.extend_from_slice(&PREPARED_COMMITMENT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.extend_from_slice(&entry.assignment.sandbox_id);
    bytes.extend_from_slice(&entry.assignment.incarnation_id);
    bytes.extend_from_slice(&entry.assignment.assignment_epoch.to_be_bytes());
    bytes.extend_from_slice(&entry.assignment.desired_generation.to_be_bytes());
    bytes.extend_from_slice(&entry.assignment.assignment_digest);
    bytes.extend_from_slice(&entry.attachment_id);
    bytes.extend_from_slice(&entry.destination_slot_id);
    bytes.extend_from_slice(&entry.source_generation.to_be_bytes());
    bytes.extend_from_slice(&entry.namespace_generation.to_be_bytes());
    bytes.extend_from_slice(&entry.desired_attachment_generation.to_be_bytes());
    bytes.extend_from_slice(&entry.resource_attachment_generation.to_be_bytes());
    bytes.extend_from_slice(&entry.source_view_id);
    bytes.extend_from_slice(&entry.source_incarnation_id.unwrap_or([0; 16]));
    bytes.push(entry.source_consistency.code());
    let source_handle_length = u16::try_from(entry.source_handle.len())
        .map_err(|_| MountError::State("catalog source handle exceeds u16".to_owned()))?;
    bytes.extend_from_slice(&source_handle_length.to_be_bytes());
    bytes.extend_from_slice(&entry.source_handle);
    bytes.extend_from_slice(&entry.source_binding_digest);
    bytes.extend_from_slice(&entry.source_realization_handle);
    bytes.extend_from_slice(&entry.source_physical_proof_digest);
    bytes.extend_from_slice(&entry.source_unique_mount_id.to_be_bytes());
    bytes.extend_from_slice(&entry.source_provider_authority_digest);
    bytes.extend_from_slice(&entry.source_provider_authority_id);
    bytes.extend_from_slice(&entry.source_provider_authority_generation.to_be_bytes());
    bytes.extend_from_slice(&entry.source_provider_resource_id);
    bytes.extend_from_slice(&entry.source_provider_resource_generation.to_be_bytes());
    bytes.extend_from_slice(&entry.source_provider_resource_digest);
    bytes.extend_from_slice(&entry.source_provider_catalog_generation.to_be_bytes());
    bytes.extend_from_slice(&entry.source_provider_catalog_digest);
    bytes.extend_from_slice(&entry.source_kernel_boot_id);
    bytes.push(entry.source_proof_class.code());
    bytes.extend_from_slice(&entry.attachment_lease_id);
    bytes.extend_from_slice(&entry.attachment_lease_issued_seconds.to_be_bytes());
    bytes.extend_from_slice(&entry.attachment_lease_expires_seconds.to_be_bytes());
    bytes.extend_from_slice(&media_length.to_be_bytes());
    bytes.extend_from_slice(media_type);
    bytes.extend_from_slice(entry.view_revision.digest().as_bytes());
    bytes.extend_from_slice(&entry.view_revision.encoded_size().to_be_bytes());
    bytes.push(u8::from(entry.prepared_scope));
    bytes.extend_from_slice(&path_length.to_be_bytes());
    bytes.extend_from_slice(relative_path);
    bytes.extend_from_slice(extra_binding);
    for (device, inode) in [
        (source.device, source.inode),
        (mount_namespace.device, mount_namespace.inode),
        (user_namespace.device, user_namespace.inode),
        (target_root.device, target_root.inode),
        (target_slot.device, target_slot.inode),
    ] {
        bytes.extend_from_slice(&device.to_be_bytes());
        bytes.extend_from_slice(&inode.to_be_bytes());
    }
    Ok(bytes)
}

fn prepared_namespace_key(request: &ValidatedMountRequest) -> PreparedNamespaceKey {
    PreparedNamespaceKey {
        sandbox_id: *request.fence().sandbox_id(),
        incarnation_id: *request.fence().incarnation_id(),
        namespace_generation: request.namespace_generation(),
    }
}

fn prepared_scope_binding(scope: &ObservedMountScope) -> PreparedScopeBinding {
    PreparedScopeBinding {
        runtime_handle: *scope.metadata().runtime_handle(),
        payload_scope_handle: *scope.metadata().payload_scope_handle(),
        root: scope.root().identity(),
        mount_namespace: scope.mount_namespace().identity(),
        user_namespace: scope.user_namespace().identity(),
    }
}

fn boottime_nanoseconds() -> Result<u64> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec)
        .map_err(|_| MountError::State("CLOCK_BOOTTIME returned negative seconds".to_owned()))?;
    let nanoseconds = u64::try_from(now.tv_nsec).map_err(|_| {
        MountError::State("CLOCK_BOOTTIME returned negative nanoseconds".to_owned())
    })?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or_else(|| MountError::State("CLOCK_BOOTTIME overflowed u64".to_owned()))
}

impl MountCatalogSnapshot {
    fn upsert(&mut self, entry: MountCatalogEntry) -> Result<bool> {
        let key = (
            entry.assignment.incarnation_id,
            entry.attachment_id,
            entry.resource_attachment_generation,
            entry.source_realization_handle,
        );
        match self.entries.binary_search_by_key(&key, |candidate| {
            (
                candidate.assignment.incarnation_id,
                candidate.attachment_id,
                candidate.resource_attachment_generation,
                candidate.source_realization_handle,
            )
        }) {
            Ok(index) if self.entries[index] == entry => return Ok(false),
            Ok(index) => self.entries[index] = entry,
            Err(index) => self.entries.insert(index, entry),
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| MountError::State("mount catalog generation overflowed".to_owned()))?;
        self.validate()?;
        Ok(true)
    }

    fn validate(&self) -> Result<()> {
        if self.generation == 0 || self.entries.len() > MAXIMUM_ENTRIES {
            return Err(MountError::State(
                "mount catalog generation or entry bound is invalid".to_owned(),
            ));
        }
        let mut previous = None;
        for entry in &self.entries {
            entry.validate()?;
            let key = (
                entry.assignment.incarnation_id,
                entry.attachment_id,
                entry.resource_attachment_generation,
                entry.source_realization_handle,
            );
            if previous.is_some_and(|value| value >= key) {
                return Err(MountError::State(
                    "mount catalog entries are not strictly ordered".to_owned(),
                ));
            }
            previous = Some(key);
        }
        Ok(())
    }
}

impl MountCatalogEntry {
    fn matches_realization(&self, expected: Option<SourceRealizationEvidenceV1>) -> bool {
        expected.is_none_or(|value| self.source_realization() == value)
    }

    fn source_realization(&self) -> SourceRealizationEvidenceV1 {
        SourceRealizationEvidenceV1 {
            handle: self.source_realization_handle,
            physical_proof_digest: self.source_physical_proof_digest,
            unique_mount_id: self.source_unique_mount_id,
            provider_authority_digest: self.source_provider_authority_digest,
            provider_authority_id: self.source_provider_authority_id,
            provider_authority_generation: self.source_provider_authority_generation,
            provider_resource_id: self.source_provider_resource_id,
            provider_resource_generation: self.source_provider_resource_generation,
            provider_resource_digest: self.source_provider_resource_digest,
            provider_catalog_generation: self.source_provider_catalog_generation,
            provider_catalog_digest: self.source_provider_catalog_digest,
            kernel_boot_id: self.source_kernel_boot_id,
            device: self.source_identity.device,
            inode: self.source_identity.inode,
            proof_class: self.source_proof_class,
        }
    }

    fn source_binding(&self) -> Result<SourceRealizationBindingV1> {
        let source = decode_view_source(&self.source_handle, DecodeLimits::default())
            .map_err(|error| MountError::State(error.to_string()))?;
        SourceRealizationBindingV1::new(
            self.source_view_id,
            self.source_generation,
            self.view_revision.clone(),
            source,
            self.source_consistency.protocol_value(),
            self.source_incarnation_id,
        )
        .map_err(|error| MountError::State(error.to_string()))
    }

    fn validate(&self) -> Result<()> {
        if self.assignment.sandbox_id == [0; 16]
            || self.assignment.incarnation_id == [0; 16]
            || self.assignment.assignment_epoch == 0
            || self.assignment.desired_generation == 0
            || self.assignment.assignment_digest == [0; 32]
            || self.attachment_id == [0; 16]
            || self.destination_slot_id == [0; 16]
            || self.source_generation == 0
            || self.namespace_generation == 0
            || self.desired_attachment_generation == 0
            || self.resource_attachment_generation == 0
            || self.desired_attachment_generation < self.resource_attachment_generation
            || self.source_view_id == [0; 16]
            || self.source_handle.is_empty()
            || self.source_binding_digest == [0; 32]
            || self.source_realization_handle == [0; 32]
            || self.source_physical_proof_digest == [0; 32]
            || self.source_unique_mount_id == 0
            || self.source_provider_authority_digest == [0; 32]
            || self.source_provider_authority_id == [0; 16]
            || self.source_provider_authority_generation == 0
            || self.source_provider_resource_id == [0; 32]
            || self.source_provider_resource_generation == 0
            || self.source_provider_resource_digest == [0; 32]
            || self.source_provider_catalog_generation == 0
            || self.source_provider_catalog_digest == [0; 32]
            || self.source_kernel_boot_id == [0; 16]
            || self.attachment_lease_id == [0; 16]
            || self.attachment_lease_expires_seconds <= self.attachment_lease_issued_seconds
            || !self.prepared_scope
            || self.commitment_version != PREPARED_COMMITMENT_VERSION
            || self.runtime_handle == [0; 32]
            || self.payload_scope_handle == [0; 32]
        {
            return Err(MountError::State(
                "mount catalog entry contains a sentinel".to_owned(),
            ));
        }
        if self.source_incarnation_id.is_some()
            != matches!(self.source_consistency, CatalogSourceConsistency::LocalLive)
            || self.source_incarnation_id == Some([0; 16])
        {
            return Err(MountError::State(
                "mount catalog source incarnation differs from its consistency contract".to_owned(),
            ));
        }
        let source = decode_view_source(&self.source_handle, DecodeLimits::default())
            .map_err(|error| MountError::State(error.to_string()))?;
        if encode_view_source(&source) != self.source_handle {
            return Err(MountError::State(
                "mount catalog source handle is not canonical".to_owned(),
            ));
        }
        let binding = self.source_binding()?;
        if binding.digest().as_bytes() != &self.source_binding_digest {
            return Err(MountError::State(
                "mount catalog source binding digest is not canonical".to_owned(),
            ));
        }
        self.source_realization().validate_for_binding(&binding)?;
        for path in [&self.target_slot_path, &self.target_relative_path] {
            validate_relative(path)?;
        }
        if !self.mount_namespace_path.is_empty()
            || !self.user_namespace_path.is_empty()
            || !self.target_root_path.is_empty()
        {
            return Err(MountError::State(
                "Host-prepared catalog entry contains obsolete static paths".to_owned(),
            ));
        }
        let expected_slot_path = destination_slot_catalog_path(
            &self.assignment.sandbox_id,
            &self.assignment.incarnation_id,
            self.namespace_generation,
            &self.destination_slot_id,
        );
        if Path::new(&self.target_slot_path) != expected_slot_path {
            return Err(MountError::State(
                "mount catalog destination does not name its broker-derived slot pin".to_owned(),
            ));
        }
        if Path::new(&self.target_relative_path)
            != payload_slot_relative_path(&self.destination_slot_id)
        {
            return Err(MountError::State(
                "Host-prepared catalog destination is not its derived payload slot".to_owned(),
            ));
        }
        for identity in [
            self.source_identity,
            self.target_root_identity,
            self.target_slot_identity,
        ] {
            if identity.device == 0 || identity.inode == 0 {
                return Err(MountError::State(
                    "mount catalog file identity contains a sentinel".to_owned(),
                ));
            }
        }
        for identity in [self.mount_namespace_identity, self.user_namespace_identity] {
            if identity.device == 0 || identity.inode == 0 {
                return Err(MountError::State(
                    "mount catalog namespace identity contains a sentinel".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn matches(&self, request: &ValidatedMountRequest) -> bool {
        let fence: &ValidatedAssignmentFence = request.fence();
        let exact_operation_authority = self.assignment.assignment_epoch
            == fence.assignment_epoch()
            && self.assignment.desired_generation == fence.desired_generation()
            && self.assignment.assignment_digest == *fence.assignment_digest()
            && self.desired_attachment_generation == request.desired_attachment_generation()
            && self.attachment_lease_id == *request.attachment_lease_id()
            && self.attachment_lease_issued_seconds == request.attachment_lease_issued_seconds()
            && self.attachment_lease_expires_seconds == request.attachment_lease_expires_seconds();
        let requested_generation = (
            fence.assignment_epoch(),
            fence.desired_generation(),
            request.desired_attachment_generation(),
        );
        let catalogued_generation = (
            self.assignment.assignment_epoch,
            self.assignment.desired_generation,
            self.desired_attachment_generation,
        );
        let current_operation_authority = requested_generation > catalogued_generation
            || (requested_generation == catalogued_generation
                && self.assignment.assignment_digest == *fence.assignment_digest());
        let authority_matches = if action_requires_live_source(request.action()) {
            exact_operation_authority
        } else {
            current_operation_authority
        };

        self.assignment.sandbox_id == *fence.sandbox_id()
            && self.assignment.incarnation_id == *fence.incarnation_id()
            && authority_matches
            && self.attachment_id == *request.attachment_id()
            && self.destination_slot_id == *request.destination_slot_id()
            && request
                .view_revision()
                .is_none_or(|revision| revision == &self.view_revision)
            && self.source_generation == request.source_generation()
            && self.namespace_generation == request.namespace_generation()
            && self.resource_attachment_generation == request.resource_attachment_generation()
            && self.source_view_id == *request.source_view_id()
            && self.source_incarnation_id.as_ref() == request.source_incarnation_id()
            && self.source_consistency.protocol_value() == request.source_consistency()
            && self.matches_source_authority(request)
    }

    fn matches_source(&self, request: &ValidatedMountRequest) -> bool {
        self.source_generation == request.source_generation()
            && self.source_view_id == *request.source_view_id()
            && self.source_incarnation_id.as_ref() == request.source_incarnation_id()
            && self.source_consistency.protocol_value() == request.source_consistency()
            && self.matches_source_authority(request)
    }

    fn matches_source_authority(&self, request: &ValidatedMountRequest) -> bool {
        self.source_handle == encode_view_source(request.source_handle())
            && request
                .source_binding()
                .is_none_or(|binding| binding.digest().as_bytes() == &self.source_binding_digest)
    }
}

fn resolve_protected_directory(root: &BeneathRoot, path: &str) -> Result<ResolvedPath> {
    root.resolve(Path::new(path), ResolveOptions::directory())
        .map_err(linux_worker_error)
}

fn resolve_payload_anchor(root: &BeneathRoot) -> Result<BeneathRoot> {
    let anchor = root
        .resolve(
            payload_anchor_relative_path(),
            ResolveOptions {
                no_mount_crossing: false,
                require_directory: true,
            },
        )
        .map_err(linux_worker_error)?;
    BeneathRoot::from_resolved(anchor).map_err(linux_worker_error)
}

fn verify_protected_slot(anchor: &ResolvedPath, slot: &ResolvedPath) -> Result<MountId> {
    let anchor_mount_id = MountId::from_fd(anchor.as_fd()).map_err(linux_worker_error)?;
    let slot_mount_id = MountId::from_fd(slot.as_fd()).map_err(linux_worker_error)?;
    if slot_mount_id != anchor_mount_id || anchor.identity() == slot.identity() {
        return Err(MountError::Worker(
            "protected destination slot is not a distinct child of its generation anchor"
                .to_owned(),
        ));
    }
    Ok(anchor_mount_id)
}

fn verify_anchor_identity(payload: &BeneathRoot, protected: &ResolvedPath) -> Result<()> {
    if payload.identity() != protected.identity() {
        return Err(MountError::Worker(
            "payload attachment anchor differs from its protected generation anchor".to_owned(),
        ));
    }
    Ok(())
}

fn verify_distinct_source(
    source: FileIdentity,
    target_slot: FileIdentity,
    attachment_anchor: FileIdentity,
) -> Result<()> {
    if source == target_slot || source == attachment_anchor || target_slot == attachment_anchor {
        return Err(MountError::Worker(
            "mount source, destination slot, and attachment anchor must be distinct".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn observe_mount_topology(
    namespace: MountNamespace<'_>,
    target_root: &BeneathRoot,
    attachment_anchor: &BeneathRoot,
    protected_anchor_mount_id: MountId,
) -> Result<ResolvedMountTopology> {
    let run = target_root
        .resolve(
            Path::new(RUN_RELATIVE_PATH),
            ResolveOptions {
                no_mount_crossing: false,
                require_directory: true,
            },
        )
        .map_err(linux_worker_error)?;
    let run_aos = target_root
        .resolve(
            Path::new(RUN_AOS_RELATIVE_PATH),
            ResolveOptions {
                no_mount_crossing: false,
                require_directory: true,
            },
        )
        .map_err(linux_worker_error)?;
    let current_anchor = target_root
        .resolve(
            payload_anchor_relative_path(),
            ResolveOptions {
                no_mount_crossing: false,
                require_directory: true,
            },
        )
        .map_err(linux_worker_error)?;

    let root_mount_id = MountId::from_fd(target_root.as_fd()).map_err(linux_worker_error)?;
    let run_mount_id = MountId::from_fd(run.as_fd()).map_err(linux_worker_error)?;
    let run_aos_mount_id = MountId::from_fd(run_aos.as_fd()).map_err(linux_worker_error)?;
    let current_anchor_mount_id =
        MountId::from_fd(current_anchor.as_fd()).map_err(linux_worker_error)?;
    let attachment_anchor_mount_id =
        MountId::from_fd(attachment_anchor.as_fd()).map_err(linux_worker_error)?;
    if current_anchor.identity() != attachment_anchor.identity() {
        return Err(MountError::Worker(
            "payload attachment-anchor descriptor is not the current path target".to_owned(),
        ));
    }
    validate_mount_path_ids(
        run_mount_id,
        run_aos_mount_id,
        current_anchor_mount_id,
        attachment_anchor_mount_id,
        protected_anchor_mount_id,
    )?;

    let inventory = namespace
        .inventory(MAXIMUM_TOPOLOGY_MOUNTS, MountListOrder::Forward)
        .map_err(linux_worker_error)?;
    let observation = |mount_id| {
        inventory
            .mounts
            .iter()
            .find(|mount| mount.mount_id == mount_id)
            .cloned()
            .ok_or_else(|| {
                MountError::Worker(
                    "complete target namespace inventory omitted a retained mount".to_owned(),
                )
            })
    };
    let root_observation = observation(root_mount_id)?;
    let run_observation = if run_mount_id == root_mount_id {
        root_observation.clone()
    } else {
        observation(run_mount_id)?
    };
    let anchor_observation = observation(attachment_anchor_mount_id)?;
    validate_mount_topology_observations(
        &root_observation,
        &run_observation,
        &anchor_observation,
        &inventory.mounts,
    )?;

    Ok(ResolvedMountTopology {
        protected_anchor_mount_id: protected_anchor_mount_id.get(),
        target_root_mount_id: root_mount_id.get(),
        run_mount_id: run_mount_id.get(),
        attachment_anchor_mount_id: attachment_anchor_mount_id.get(),
        target_mount_namespace_id: root_observation.mount_namespace_id,
        attachment_anchor_mount_attributes: anchor_observation.mount_attributes,
        attachment_anchor_idmap_digest: digest_idmaps(&anchor_observation),
    })
}

fn validate_mount_path_ids(
    run: MountId,
    run_aos: MountId,
    current_anchor: MountId,
    attachment_anchor: MountId,
    protected_anchor: MountId,
) -> Result<()> {
    if run_aos != run
        || current_anchor != attachment_anchor
        || attachment_anchor == run
        || attachment_anchor == protected_anchor
    {
        return Err(MountError::Worker(
            "payload attachment-anchor path contains an untrusted mount crossing".to_owned(),
        ));
    }
    Ok(())
}

fn validate_mount_topology_observations(
    root: &MountObservation,
    run: &MountObservation,
    anchor: &MountObservation,
    mounts: &[MountObservation],
) -> Result<()> {
    validate_complete_mount_tree(root.mount_id, mounts)?;

    let namespace_id = root.mount_namespace_id;
    let mount_ids = mounts
        .iter()
        .map(|mount| mount.mount_id)
        .collect::<BTreeSet<_>>();
    let mount_point_count = |expected: &[u8]| {
        mounts
            .iter()
            .filter(|mount| mount.mount_point.as_os_str().as_bytes() == expected)
            .count()
    };
    if namespace_id == 0
        || mounts
            .iter()
            .any(|mount| mount.mount_namespace_id != namespace_id)
        || !mount_ids.contains(&run.mount_id)
        || !mount_ids.contains(&anchor.mount_id)
        || root.mount_point.as_os_str().as_bytes() != ROOT_MOUNT_POINT
        || mount_point_count(ROOT_MOUNT_POINT) != 1
        || (run.mount_id == root.mount_id
            && (run.mount_point.as_os_str().as_bytes() != ROOT_MOUNT_POINT
                || mount_point_count(RUN_MOUNT_POINT) != 0))
        || (run.mount_id != root.mount_id
            && (run.mount_point.as_os_str().as_bytes() != RUN_MOUNT_POINT
                || run.parent_mount_id != root.mount_id
                || mount_point_count(RUN_MOUNT_POINT) != 1))
        || mount_point_count(RUN_AOS_MOUNT_POINT) != 0
        || anchor.mount_point.as_os_str().as_bytes() != ATTACHMENT_ANCHOR_MOUNT_POINT
        || anchor.parent_mount_id != run.mount_id
        || mount_point_count(ATTACHMENT_ANCHOR_MOUNT_POINT) != 1
        || anchor.mount_attributes & REQUIRED_ATTACHMENT_ANCHOR_ATTRIBUTES
            != REQUIRED_ATTACHMENT_ANCHOR_ATTRIBUTES
        || anchor.uid_map.as_ref().is_none_or(Vec::is_empty)
        || anchor.gid_map.as_ref().is_none_or(Vec::is_empty)
    {
        return Err(MountError::Worker(
            "payload attachment-anchor topology, attributes, or idmap evidence is invalid"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Validates one complete parent tree rooted at the selected namespace root.
///
/// Proven-root memoization follows each parent edge at most once, keeping the
/// total work `O(n log n)` with the ordered maps and sets used here.
fn validate_complete_mount_tree(root: MountId, mounts: &[MountObservation]) -> Result<()> {
    let parents = mounts
        .iter()
        .map(|mount| (mount.mount_id, mount.parent_mount_id))
        .collect::<BTreeMap<_, _>>();
    let invalid_tree = || {
        MountError::Worker("payload mount inventory is not one complete namespace tree".to_owned())
    };

    if parents.len() != mounts.len() {
        return Err(invalid_tree());
    }
    let root_parent = parents.get(&root).ok_or_else(&invalid_tree)?;
    if parents.contains_key(root_parent) {
        return Err(invalid_tree());
    }

    let mut proven = BTreeSet::from([root]);
    for mount_id in parents.keys().copied() {
        if proven.contains(&mount_id) {
            continue;
        }

        let mut path = Vec::new();
        let mut visited = BTreeSet::new();
        let mut current = mount_id;

        while !proven.contains(&current) {
            if !visited.insert(current) {
                return Err(invalid_tree());
            }
            path.push(current);
            current = *parents.get(&current).ok_or_else(&invalid_tree)?;
        }

        proven.extend(path);
    }

    Ok(())
}

pub(crate) fn digest_idmaps(mount: &MountObservation) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.mount.idmaps.v1\0");
    for map in [&mount.uid_map, &mount.gid_map] {
        match map {
            None => digest.update([0]),
            Some(extents) => {
                digest.update([1]);
                digest.update(
                    u64::try_from(extents.len())
                        .unwrap_or(u64::MAX)
                        .to_le_bytes(),
                );
                for extent in extents {
                    digest.update(
                        u64::try_from(extent.len())
                            .unwrap_or(u64::MAX)
                            .to_le_bytes(),
                    );
                    digest.update(extent.as_bytes());
                }
            }
        }
    }
    digest.finalize().into()
}

fn linux_worker_error(error: aos_sandbox_linux::Error) -> MountError {
    MountError::Worker(error.to_string())
}

fn verify_file(actual: FileIdentity, expected: FileIdentityWire, label: &str) -> Result<()> {
    if actual.device != expected.device || actual.inode != expected.inode {
        return Err(MountError::Worker(format!(
            "catalogued {label} descriptor identity changed"
        )));
    }
    Ok(())
}

fn verify_namespace(
    actual: NamespaceIdentity,
    expected: NamespaceIdentityWire,
    label: &str,
) -> Result<()> {
    if actual.device != expected.device || actual.inode != expected.inode {
        return Err(MountError::Worker(format!(
            "catalogued {label} identity changed"
        )));
    }
    Ok(())
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| MountError::State("derived mount catalog path is not UTF-8".to_owned()))
}

fn sync_directory(root: &BeneathRoot) -> Result<()> {
    let descriptor = rustix::fs::openat(
        root.as_fd(),
        ".",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| MountError::State(error.to_string()))?;
    rustix::fs::fsync(&descriptor).map_err(|error| MountError::State(error.to_string()))
}

fn validate_relative(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > MAXIMUM_RELATIVE_PATH_BYTES
        || path.as_bytes().contains(&0)
        || Path::new(path).is_absolute()
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
        || Path::new(path)
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(MountError::State(
            "mount catalog path is not a normalized relative path".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_proto::aos::sandbox::local::v1::{
        ApplyMountRequest, AssignmentFence, Audience, MountAction, RequestHeader,
    };
    use aos_sandbox_linux::path::FileType;
    use aos_sandbox_protocol::{PeerCredentials, PeerPolicy, decode_mount_request};
    use buffa::Message as _;
    use std::os::unix::ffi::OsStringExt as _;

    use super::*;

    fn file_catalog(path: &Path) -> FileMountCatalog {
        let descriptor = rustix::fs::open(
            path,
            rustix::fs::OFlags::PATH
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();

        FileMountCatalog {
            root: BeneathRoot::from_owned(descriptor).unwrap(),
        }
    }

    fn catalog_entry() -> MountCatalogEntry {
        let descriptor = ObjectDescriptor::new(
            aos_sandbox_core::MediaType::new("application/vnd.aos.sandbox.view.v1+cbor".to_owned())
                .unwrap(),
            aos_sandbox_core::ObjectDigest::from_bytes([7; 32]),
            10,
        );

        let mut entry = MountCatalogEntry {
            assignment: CatalogAssignment {
                sandbox_id: [1; 16],
                incarnation_id: [2; 16],
                assignment_epoch: 1,
                desired_generation: 1,
                assignment_digest: [3; 32],
            },
            attachment_id: [4; 16],
            destination_slot_id: [5; 16],
            view_revision: descriptor,
            source_generation: 1,
            namespace_generation: 1,
            desired_attachment_generation: 1,
            resource_attachment_generation: 1,
            source_view_id: [6; 16],
            source_incarnation_id: None,
            source_consistency: CatalogSourceConsistency::ImmutableRevision,
            source_handle: Vec::new(),
            source_binding_digest: [0; 32],
            source_realization_handle: [24; 32],
            source_physical_proof_digest: [25; 32],
            source_unique_mount_id: 26,
            source_provider_authority_digest: [27; 32],
            source_provider_authority_id: [33; 16],
            source_provider_authority_generation: 34,
            source_provider_resource_id: [28; 32],
            source_provider_resource_generation: 29,
            source_provider_resource_digest: [30; 32],
            source_provider_catalog_generation: 31,
            source_provider_catalog_digest: [32; 32],
            source_kernel_boot_id: [35; 16],
            source_proof_class: SourcePinProofClassV1::ImmutableTree,
            attachment_lease_id: [8; 16],
            attachment_lease_issued_seconds: 9,
            attachment_lease_expires_seconds: 10,
            mount_namespace_path: String::new(),
            user_namespace_path: String::new(),
            target_root_path: String::new(),
            target_slot_path: destination_slot_catalog_path(&[1; 16], &[2; 16], 1, &[5; 16])
                .to_string_lossy()
                .into_owned(),
            target_relative_path: payload_slot_relative_path(&[5; 16])
                .to_string_lossy()
                .into_owned(),
            prepared_scope: true,
            commitment_version: PREPARED_COMMITMENT_VERSION,
            runtime_handle: [14; 32],
            payload_scope_handle: [15; 32],
            source_identity: FileIdentityWire {
                device: 1,
                inode: 1,
            },
            mount_namespace_identity: NamespaceIdentityWire {
                device: 1,
                inode: 2,
            },
            user_namespace_identity: NamespaceIdentityWire {
                device: 1,
                inode: 3,
            },
            target_root_identity: FileIdentityWire {
                device: 1,
                inode: 4,
            },
            target_slot_identity: FileIdentityWire {
                device: 1,
                inode: 5,
            },
        };
        bind_current_source(&mut entry);
        entry
    }

    fn prepared_catalog_entry() -> MountCatalogEntry {
        catalog_entry()
    }

    fn validated_detach(
        entry: &MountCatalogEntry,
        assignment_epoch: u64,
        desired_generation: u64,
        desired_attachment_generation: u64,
        assignment_digest: [u8; 32],
    ) -> ValidatedMountRequest {
        let request = ApplyMountRequest {
            header: Some(RequestHeader {
                protocol_major: 2,
                protocol_minor: 0,
                request_id: vec![91; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 100,
                maximum_response_bytes: 4096,
                ..Default::default()
            })
            .into(),
            fence: Some(AssignmentFence {
                sandbox_id: entry.assignment.sandbox_id.to_vec(),
                incarnation_id: entry.assignment.incarnation_id.to_vec(),
                assignment_epoch,
                desired_generation,
                assignment_digest: assignment_digest.to_vec(),
                ..Default::default()
            })
            .into(),
            action: MountAction::MOUNT_ACTION_DETACH.into(),
            attachment_id: entry.attachment_id.to_vec(),
            destination_slot_id: entry.destination_slot_id.to_vec(),
            source_generation: entry.source_generation,
            namespace_generation: entry.namespace_generation,
            desired_attachment_generation,
            resource_attachment_generation: entry.resource_attachment_generation,
            source_view_id: entry.source_view_id.to_vec(),
            source_incarnation_id: entry
                .source_incarnation_id
                .map_or_else(Vec::new, |value| value.to_vec()),
            source_consistency: entry.source_consistency.protocol_value().into(),
            source_handle: entry.source_handle.clone(),
            attachment_lease_id: vec![99; 16],
            attachment_lease_issued_seconds: 20,
            attachment_lease_expires_seconds: 30,
            detached_mount_handle: vec![92; 32],
            ..Default::default()
        };
        decode_mount_request(
            &request.encode_to_vec(),
            PeerCredentials {
                uid: 811,
                gid: 811,
                pid: Some(1),
            },
            PeerPolicy {
                uid: 811,
                gid: Some(811),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            10,
        )
        .unwrap()
    }

    fn bind_current_source(entry: &mut MountCatalogEntry) {
        let source = aos_sandbox_core::model::ViewSource::ImmutableTree {
            tree: ObjectDescriptor::new(
                aos_sandbox_core::MediaType::new(
                    "application/vnd.aos.sandbox.tree.v1+cbor".to_owned(),
                )
                .unwrap(),
                ObjectDigest::from_bytes([22; 32]),
                23,
            ),
        };
        entry.source_handle = encode_view_source(&source);
        let binding = SourceRealizationBindingV1::new(
            entry.source_view_id,
            entry.source_generation,
            entry.view_revision.clone(),
            source,
            entry.source_consistency.protocol_value(),
            entry.source_incarnation_id,
        )
        .unwrap();
        entry.source_binding_digest = *binding.digest().as_bytes();

        let realization = SourceRealizationEvidenceV1::authenticated_fixture(
            &binding,
            25,
            entry.source_kernel_boot_id,
        )
        .unwrap();
        entry.source_realization_handle = realization.handle;
        entry.source_physical_proof_digest = realization.physical_proof_digest;
        entry.source_unique_mount_id = realization.unique_mount_id;
        entry.source_provider_authority_digest = realization.provider_authority_digest;
        entry.source_provider_authority_id = realization.provider_authority_id;
        entry.source_provider_authority_generation = realization.provider_authority_generation;
        entry.source_provider_resource_id = realization.provider_resource_id;
        entry.source_provider_resource_generation = realization.provider_resource_generation;
        entry.source_provider_resource_digest = realization.provider_resource_digest;
        entry.source_provider_catalog_generation = realization.provider_catalog_generation;
        entry.source_provider_catalog_digest = realization.provider_catalog_digest;
        entry.source_identity.device = realization.device;
        entry.source_identity.inode = realization.inode;
    }

    fn prepared_binding() -> PreparedScopeBinding {
        PreparedScopeBinding {
            runtime_handle: [14; 32],
            payload_scope_handle: [15; 32],
            root: FileIdentity {
                device: 1,
                inode: 4,
                file_type: FileType::Directory,
            },
            mount_namespace: NamespaceIdentity {
                device: 1,
                inode: 2,
            },
            user_namespace: NamespaceIdentity {
                device: 1,
                inode: 3,
            },
        }
    }

    fn topology() -> ResolvedMountTopology {
        ResolvedMountTopology {
            protected_anchor_mount_id: 14,
            target_root_mount_id: 15,
            run_mount_id: 15,
            attachment_anchor_mount_id: 16,
            target_mount_namespace_id: 17,
            attachment_anchor_mount_attributes: REQUIRED_ATTACHMENT_ANCHOR_ATTRIBUTES,
            attachment_anchor_idmap_digest: [21; 32],
        }
    }

    fn mount_observation(
        mount_id: u64,
        parent_mount_id: u64,
        namespace_id: u64,
        mount_point: &[u8],
    ) -> MountObservation {
        MountObservation {
            mount_id: MountId::new(mount_id).unwrap(),
            parent_mount_id: MountId::new(parent_mount_id).unwrap(),
            mount_namespace_id: namespace_id,
            device_major: 0,
            device_minor: 1,
            superblock_magic: 0x0102_1994,
            superblock_flags: 0,
            mount_attributes: REQUIRED_ATTACHMENT_ANCHOR_ATTRIBUTES,
            propagation: 0,
            supported_mask: Some(u64::MAX),
            root: std::ffi::OsString::from_vec(b"/".to_vec()),
            mount_point: std::ffi::OsString::from_vec(mount_point.to_vec()),
            filesystem_type: std::ffi::OsString::from_vec(b"tmpfs".to_vec()),
            superblock_source: std::ffi::OsString::from_vec(b"tmpfs".to_vec()),
            uid_map: Some(vec!["0 100000 65536".to_owned()]),
            gid_map: Some(vec!["0 100000 65536".to_owned()]),
        }
    }

    #[test]
    fn catalog_paths_reject_traversal_and_noncanonical_forms() {
        assert!(validate_relative("resources/source").is_ok());
        for invalid in ["", "/absolute", "../escape", "a/../b", "a//b", "./a"] {
            assert!(validate_relative(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn only_create_requires_a_live_source_descriptor() {
        assert!(action_requires_live_source(
            MountAction::MOUNT_ACTION_CREATE_DETACHED
        ));
        for action in [
            MountAction::MOUNT_ACTION_INSTALL,
            MountAction::MOUNT_ACTION_REPLACE,
            MountAction::MOUNT_ACTION_DETACH,
            MountAction::MOUNT_ACTION_RELEASE,
        ] {
            assert!(!action_requires_live_source(action));
        }
    }

    #[test]
    fn prepared_commitment_binds_all_behavior_facts() {
        let entry = catalog_entry();
        entry.validate().unwrap();

        let directory = |device, inode| FileIdentity {
            device,
            inode,
            file_type: FileType::Directory,
        };
        let binding = prepared_binding();
        let topology = topology();
        let commitment = prepared_catalog_authorization_commitment(
            1,
            &entry,
            binding,
            directory(1, 1),
            directory(1, 5),
            topology,
            directory(12, 13),
        )
        .unwrap();

        let commit = |generation, candidate: &MountCatalogEntry| {
            prepared_catalog_authorization_commitment(
                generation,
                candidate,
                binding,
                directory(1, 1),
                directory(1, 5),
                topology,
                directory(12, 13),
            )
            .unwrap()
        };
        assert_ne!(commit(2, &entry), commitment);

        let mut changed_path = entry.clone();
        changed_path.target_relative_path = "run/aos/attachments/other".to_owned();
        assert_ne!(commit(1, &changed_path), commitment);

        let mut changed_attachment_generation = entry.clone();
        changed_attachment_generation.desired_attachment_generation += 1;
        assert_ne!(commit(1, &changed_attachment_generation), commitment);

        let mut changed_resource_generation = entry.clone();
        changed_resource_generation.resource_attachment_generation += 1;
        assert_ne!(commit(1, &changed_resource_generation), commitment);

        let mut changed_source = entry.clone();
        changed_source.source_handle[0] ^= 1;
        assert_ne!(commit(1, &changed_source), commitment);

        let mut changed_lease = entry.clone();
        changed_lease.attachment_lease_id = [12; 16];
        assert_ne!(commit(1, &changed_lease), commitment);

        let mut changed_topology = topology;
        changed_topology.attachment_anchor_mount_id += 1;
        assert_ne!(
            prepared_catalog_authorization_commitment(
                1,
                &entry,
                binding,
                directory(1, 1),
                directory(1, 5),
                changed_topology,
                directory(12, 13),
            )
            .unwrap(),
            commitment
        );

        let snapshot = MountCatalogSnapshot {
            generation: 1,
            entries: vec![entry.clone(), entry],
        };
        assert!(snapshot.validate().is_err());
    }

    #[test]
    fn host_prepared_entries_exclude_reopenable_scope_paths() {
        let entry = catalog_entry();
        entry.validate().unwrap();

        let mut obsolete_paths = entry.clone();
        obsolete_paths.mount_namespace_path = "pins/mntns".to_owned();
        assert!(obsolete_paths.validate().is_err());

        let mut missing_source = entry.clone();
        missing_source.source_handle.clear();
        assert!(missing_source.validate().is_err());

        let mut mismatched_binding = entry.clone();
        mismatched_binding.source_binding_digest[0] ^= 1;
        assert!(mismatched_binding.validate().is_err());

        let mut missing_runtime = entry.clone();
        missing_runtime.runtime_handle = [0; 32];
        assert!(missing_runtime.validate().is_err());

        let mut unknown_version = entry;
        unknown_version.commitment_version = 3;
        assert!(unknown_version.validate().is_err());
    }

    #[test]
    fn retired_static_source_path_schema_is_rejected() {
        let mut encoded = serde_json::to_value(catalog_entry()).unwrap();
        encoded["source_path"] = serde_json::Value::String("sources/legacy".to_owned());
        assert!(serde_json::from_value::<MountCatalogEntry>(encoded).is_err());
    }

    #[test]
    fn catalog_rejects_a_provider_or_caller_selected_realization_handle() {
        let mut entry = catalog_entry();
        entry.source_realization_handle[0] ^= 1;

        assert!(entry.validate().is_err());
    }

    #[test]
    fn commitment_changes_for_every_source_realization_field() {
        let entry = catalog_entry();
        let directory = |device, inode| FileIdentity {
            device,
            inode,
            file_type: FileType::Directory,
        };
        let commit = |candidate: &MountCatalogEntry| {
            prepared_catalog_authorization_commitment(
                1,
                candidate,
                prepared_binding(),
                directory(1, 1),
                directory(1, 5),
                topology(),
                directory(12, 13),
            )
            .unwrap()
        };
        let baseline = commit(&entry);
        let mut changed = Vec::new();
        macro_rules! changed_entry {
            ($field:ident, $value:expr) => {{
                let mut candidate = entry.clone();
                candidate.$field = $value;
                changed.push(candidate);
            }};
        }
        changed_entry!(source_realization_handle, [41; 32]);
        changed_entry!(source_physical_proof_digest, [42; 32]);
        changed_entry!(source_unique_mount_id, 43);
        changed_entry!(source_provider_authority_digest, [44; 32]);
        changed_entry!(source_provider_authority_id, [45; 16]);
        changed_entry!(source_provider_authority_generation, 46);
        changed_entry!(source_provider_resource_id, [47; 32]);
        changed_entry!(source_provider_resource_generation, 48);
        changed_entry!(source_provider_resource_digest, [49; 32]);
        changed_entry!(source_provider_catalog_generation, 50);
        changed_entry!(source_provider_catalog_digest, [51; 32]);
        changed_entry!(source_kernel_boot_id, [52; 16]);
        changed_entry!(source_proof_class, SourcePinProofClassV1::LocalLive);
        for candidate in changed {
            assert_ne!(commit(&candidate), baseline);
        }
        assert_ne!(
            prepared_catalog_authorization_commitment(
                1,
                &entry,
                prepared_binding(),
                directory(53, 54),
                directory(1, 5),
                topology(),
                directory(12, 13),
            )
            .unwrap(),
            baseline
        );
    }

    #[test]
    fn prepared_commitment_has_final_v2_golden_and_binds_topology_and_source() {
        let directory = |device, inode| FileIdentity {
            device,
            inode,
            file_type: FileType::Directory,
        };
        let binding = prepared_binding();
        let current = prepared_catalog_entry();
        current.validate().unwrap();
        let commitment = prepared_catalog_authorization_commitment(
            1,
            &current,
            binding,
            directory(1, 1),
            directory(1, 5),
            topology(),
            directory(12, 13),
        )
        .unwrap();
        assert_eq!(
            commitment.digest().as_bytes(),
            &[
                0xeb, 0xcf, 0xc3, 0x21, 0x9c, 0xae, 0xca, 0x27, 0x90, 0x95, 0xc1, 0xe5, 0x19, 0x95,
                0xa9, 0x8e, 0xdb, 0xb0, 0x13, 0x25, 0xc2, 0x6a, 0xbd, 0xbf, 0x43, 0x5f, 0x0a, 0x59,
                0x7f, 0x5b, 0xf4, 0x9c,
            ]
        );

        let encoded = serde_json::to_vec(&current).unwrap();
        assert!(
            encoded
                .windows(b"\"commitment_version\":2".len())
                .any(|window| window == b"\"commitment_version\":2")
        );
        for required_field in [b"source_handle".as_slice(), b"source_binding_digest"] {
            assert!(
                encoded
                    .windows(required_field.len())
                    .any(|window| window == required_field)
            );
        }

        let baseline_topology = topology();
        let mut changed_topologies = Vec::new();
        for change in 0..7 {
            let mut changed = baseline_topology;
            match change {
                0 => changed.protected_anchor_mount_id += 1,
                1 => changed.target_root_mount_id += 1,
                2 => changed.run_mount_id += 1,
                3 => changed.attachment_anchor_mount_id += 1,
                4 => changed.target_mount_namespace_id += 1,
                5 => changed.attachment_anchor_mount_attributes ^= 0x10,
                6 => changed.attachment_anchor_idmap_digest[0] ^= 1,
                _ => unreachable!(),
            }
            changed_topologies.push(changed);
        }
        for changed_topology in changed_topologies {
            assert_ne!(
                prepared_catalog_authorization_commitment(
                    1,
                    &current,
                    binding,
                    directory(1, 1),
                    directory(1, 5),
                    changed_topology,
                    directory(12, 13),
                )
                .unwrap(),
                commitment
            );
        }
        assert_ne!(
            prepared_catalog_authorization_commitment(
                1,
                &current,
                binding,
                directory(1, 1),
                directory(1, 5),
                baseline_topology,
                directory(12, 14),
            )
            .unwrap(),
            commitment
        );
    }

    #[test]
    fn production_catalog_reconstructs_historical_teardown_without_provider() {
        let directory = tempfile::tempdir().unwrap();
        let file_catalog = file_catalog(directory.path());
        let mut entry = catalog_entry();
        entry.assignment.desired_generation = 2;
        entry.assignment.assignment_digest = [60; 32];
        entry.desired_attachment_generation = 2;
        file_catalog
            .publish_snapshot(&MountCatalogSnapshot {
                generation: 1,
                entries: vec![entry.clone()],
            })
            .unwrap();
        let catalog = PreparedMountCatalog::new(file_catalog);
        let newer = validated_detach(&entry, 1, 3, 3, [61; 32]);

        assert!(catalog.supports_existing_resource_actions());
        assert!(catalog.supports_catalog_preparation());
        assert!(
            catalog
                .source_pins
                .resolve(&entry.source_binding().unwrap())
                .is_err()
        );
        assert!(
            catalog
                .catalog
                .contains_matching_entry(&newer, Some(entry.source_realization()))
                .unwrap()
        );
        let (_, reconstructed) = catalog
            .catalog
            .matching_entry(&newer, Some(entry.source_realization()))
            .unwrap();
        assert_eq!(
            reconstructed.source_binding().unwrap(),
            entry.source_binding().unwrap()
        );
        assert_eq!(
            reconstructed.source_realization(),
            entry.source_realization()
        );
        assert_eq!(reconstructed.resource_attachment_generation, 1);
        assert_eq!(newer.fence().desired_generation(), 3);
        assert_eq!(newer.desired_attachment_generation(), 3);
    }

    #[test]
    fn catalog_preparation_rejects_a_regular_file_source_before_commitment() {
        assert!(
            require_preparation_source_directory(FileIdentity {
                device: 1,
                inode: 2,
                file_type: FileType::Regular,
            })
            .is_err()
        );
        assert!(
            require_preparation_source_directory(FileIdentity {
                device: 1,
                inode: 2,
                file_type: FileType::Directory,
            })
            .is_ok()
        );
    }

    #[test]
    fn historical_catalog_recipe_accepts_only_monotonic_current_teardown_authority() {
        let mut entry = catalog_entry();
        entry.assignment.desired_generation = 2;
        entry.assignment.assignment_digest = [60; 32];
        entry.desired_attachment_generation = 2;

        let newer = validated_detach(&entry, 1, 3, 3, [61; 32]);
        assert!(entry.matches(&newer));

        let same_generation_equivocation = validated_detach(&entry, 1, 2, 2, [61; 32]);
        assert!(!entry.matches(&same_generation_equivocation));

        let rollback = validated_detach(&entry, 1, 1, 1, [3; 32]);
        assert!(!entry.matches(&rollback));
    }

    #[test]
    fn payload_topology_accepts_root_backed_and_distinct_run_mounts() {
        let root = mount_observation(30, 29, 90, b"/");
        let anchor_from_root = mount_observation(32, 30, 90, ATTACHMENT_ANCHOR_MOUNT_POINT);
        let root_backed = [root.clone(), anchor_from_root.clone()];
        assert!(
            validate_mount_topology_observations(&root, &root, &anchor_from_root, &root_backed,)
                .is_ok()
        );

        let run = mount_observation(31, 30, 90, b"/run");
        let anchor_from_run = mount_observation(32, 31, 90, ATTACHMENT_ANCHOR_MOUNT_POINT);
        let unrelated = mount_observation(40, 31, 90, b"/run/unrelated");
        let distinct_run = [
            root.clone(),
            run.clone(),
            anchor_from_run.clone(),
            unrelated,
        ];
        assert!(
            validate_mount_topology_observations(&root, &run, &anchor_from_run, &distinct_run,)
                .is_ok()
        );
    }

    #[test]
    fn payload_topology_rejects_wrong_parent_path_namespace_attributes_and_idmaps() {
        let root = mount_observation(30, 29, 90, b"/");
        let run = mount_observation(31, 30, 90, b"/run");
        let anchor = mount_observation(32, 31, 90, ATTACHMENT_ANCHOR_MOUNT_POINT);

        let mut cases = Vec::new();
        let mut wrong_root_parent = root.clone();
        wrong_root_parent.parent_mount_id = run.mount_id;
        cases.push((wrong_root_parent, run.clone(), anchor.clone()));
        let mut wrong_run_path = run.clone();
        wrong_run_path.mount_point = std::ffi::OsString::from("/other");
        cases.push((root.clone(), wrong_run_path, anchor.clone()));
        let mut wrong_run_parent = run.clone();
        wrong_run_parent.parent_mount_id = MountId::new(29).unwrap();
        cases.push((root.clone(), wrong_run_parent, anchor.clone()));
        let mut wrong_anchor_path = anchor.clone();
        wrong_anchor_path.mount_point = std::ffi::OsString::from("/run/aos/other");
        cases.push((root.clone(), run.clone(), wrong_anchor_path));
        let mut wrong_anchor_parent = anchor.clone();
        wrong_anchor_parent.parent_mount_id = root.mount_id;
        cases.push((root.clone(), run.clone(), wrong_anchor_parent));
        let mut wrong_namespace = anchor.clone();
        wrong_namespace.mount_namespace_id += 1;
        cases.push((root.clone(), run.clone(), wrong_namespace));
        let mut writable = anchor.clone();
        writable.mount_attributes &= !0x1;
        cases.push((root.clone(), run.clone(), writable));
        let mut absent_uid_map = anchor.clone();
        absent_uid_map.uid_map = None;
        cases.push((root.clone(), run.clone(), absent_uid_map));
        let mut empty_gid_map = anchor;
        empty_gid_map.gid_map = Some(Vec::new());
        cases.push((root.clone(), run.clone(), empty_gid_map));

        for (candidate_root, candidate_run, candidate_anchor) in cases {
            let inventory = [
                candidate_root.clone(),
                candidate_run.clone(),
                candidate_anchor.clone(),
            ];
            assert!(
                validate_mount_topology_observations(
                    &candidate_root,
                    &candidate_run,
                    &candidate_anchor,
                    &inventory,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn payload_topology_requires_a_complete_unique_namespace_tree() {
        let root = mount_observation(30, 29, 90, b"/");
        let run = mount_observation(31, 30, 90, RUN_MOUNT_POINT);
        let anchor = mount_observation(32, 31, 90, ATTACHMENT_ANCHOR_MOUNT_POINT);

        assert!(
            validate_mount_topology_observations(
                &root,
                &run,
                &anchor,
                &[run.clone(), anchor.clone()],
            )
            .is_err()
        );

        let duplicate_root = mount_observation(33, 30, 90, ROOT_MOUNT_POINT);
        assert!(
            validate_mount_topology_observations(
                &root,
                &run,
                &anchor,
                &[root.clone(), run.clone(), anchor.clone(), duplicate_root],
            )
            .is_err()
        );

        let mut parent_present_root = root.clone();
        parent_present_root.parent_mount_id = MountId::new(33).unwrap();
        let parent = mount_observation(33, 29, 90, b"/outside");
        assert!(
            validate_mount_topology_observations(
                &parent_present_root,
                &run,
                &anchor,
                &[
                    parent_present_root.clone(),
                    run.clone(),
                    anchor.clone(),
                    parent
                ],
            )
            .is_err()
        );

        let orphan = mount_observation(40, 99, 90, b"/orphan");
        assert!(
            validate_mount_topology_observations(
                &root,
                &run,
                &anchor,
                &[root.clone(), run.clone(), anchor.clone(), orphan],
            )
            .is_err()
        );

        let cycle_first = mount_observation(40, 41, 90, b"/cycle/first");
        let cycle_second = mount_observation(41, 40, 90, b"/cycle/second");
        assert!(
            validate_mount_topology_observations(
                &root,
                &run,
                &anchor,
                &[
                    root.clone(),
                    run.clone(),
                    anchor.clone(),
                    cycle_first,
                    cycle_second,
                ],
            )
            .is_err()
        );

        for extra in [
            mount_observation(33, 31, 90, RUN_AOS_MOUNT_POINT),
            mount_observation(33, 31, 90, ATTACHMENT_ANCHOR_MOUNT_POINT),
        ] {
            assert!(
                validate_mount_topology_observations(
                    &root,
                    &run,
                    &anchor,
                    &[root.clone(), run.clone(), anchor.clone(), extra],
                )
                .is_err()
            );
        }
    }

    #[test]
    fn complete_mount_tree_handles_a_long_reverse_ordered_chain() {
        const CHAIN_LENGTH: u64 = 4_096;

        // The smallest ID is deepest and the selected root is last, forcing a
        // full initial walk while memoization makes every later lookup constant-depth.
        let root_id = MountId::new(CHAIN_LENGTH + 1).unwrap();
        let mut mounts = (1..=CHAIN_LENGTH)
            .map(|mount_id| mount_observation(mount_id, mount_id + 1, 90, b"/chain"))
            .collect::<Vec<_>>();
        mounts.push(mount_observation(
            root_id.get(),
            CHAIN_LENGTH + 2,
            90,
            ROOT_MOUNT_POINT,
        ));

        assert!(validate_complete_mount_tree(root_id, &mounts).is_ok());
    }

    #[cfg(feature = "kernel-tests")]
    #[test]
    #[ignore = "requires a root VM with Linux 6.18 statmount/listmount support"]
    fn live_namespace_root_is_unique_and_has_an_external_parent() {
        assert!(rustix::process::geteuid().is_root());
        let inventory = MountNamespace::current()
            .inventory(MAXIMUM_TOPOLOGY_MOUNTS, MountListOrder::Forward)
            .unwrap();
        let roots = inventory
            .mounts
            .iter()
            .filter(|mount| mount.mount_point.as_os_str().as_bytes() == ROOT_MOUNT_POINT)
            .collect::<Vec<_>>();
        assert_eq!(roots.len(), 1);

        let mount_ids = inventory
            .mounts
            .iter()
            .map(|mount| mount.mount_id)
            .collect::<BTreeSet<_>>();
        assert!(!mount_ids.contains(&roots[0].parent_mount_id));
    }

    #[test]
    fn payload_topology_rejects_intermediate_and_covered_anchor_mounts() {
        let mount = |value| MountId::new(value).unwrap();
        assert!(
            validate_mount_path_ids(mount(30), mount(30), mount(31), mount(31), mount(29)).is_ok()
        );
        assert!(
            validate_mount_path_ids(mount(30), mount(32), mount(31), mount(31), mount(29)).is_err()
        );
        assert!(
            validate_mount_path_ids(mount(30), mount(30), mount(32), mount(31), mount(29)).is_err()
        );
        assert!(
            validate_mount_path_ids(mount(30), mount(30), mount(31), mount(30), mount(29)).is_err()
        );
        assert!(
            validate_mount_path_ids(mount(30), mount(30), mount(31), mount(31), mount(31)).is_err()
        );
    }

    #[test]
    fn catalog_rejects_same_inode_source_slot_and_anchor_aliases() {
        let directory = |inode| FileIdentity {
            device: 1,
            inode,
            file_type: FileType::Directory,
        };
        assert!(verify_distinct_source(directory(1), directory(2), directory(3)).is_ok());
        assert!(verify_distinct_source(directory(2), directory(2), directory(3)).is_err());
        assert!(verify_distinct_source(directory(3), directory(2), directory(3)).is_err());
        assert!(verify_distinct_source(directory(1), directory(3), directory(3)).is_err());
    }

    #[test]
    fn catalog_snapshot_publication_is_atomic_and_exact() {
        let directory = tempfile::tempdir().unwrap();
        let descriptor = rustix::fs::open(
            directory.path(),
            rustix::fs::OFlags::PATH
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let catalog = FileMountCatalog {
            root: BeneathRoot::from_owned(descriptor).unwrap(),
        };
        assert_eq!(
            catalog.snapshot_or_empty().unwrap(),
            MountCatalogSnapshot {
                generation: 0,
                entries: Vec::new(),
            }
        );

        std::fs::write(directory.path().join(CATALOG_NEXT_FILE), b"interrupted").unwrap();
        let first = MountCatalogSnapshot {
            generation: 1,
            entries: vec![catalog_entry()],
        };
        catalog.publish_snapshot(&first).unwrap();
        assert_eq!(catalog.snapshot().unwrap(), first);
        assert!(!directory.path().join(CATALOG_NEXT_FILE).exists());
        assert_eq!(
            std::fs::metadata(directory.path().join(CATALOG_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let second = MountCatalogSnapshot {
            generation: 2,
            entries: vec![catalog_entry()],
        };
        catalog.publish_snapshot(&second).unwrap();
        assert_eq!(catalog.snapshot().unwrap(), second);
    }

    #[test]
    fn catalog_upsert_is_stable_and_keeps_strict_key_order() {
        let mut snapshot = MountCatalogSnapshot {
            generation: 0,
            entries: Vec::new(),
        };
        let original = catalog_entry();
        assert!(snapshot.upsert(original.clone()).unwrap());
        assert_eq!(snapshot.generation, 1);
        assert!(!snapshot.upsert(original.clone()).unwrap());
        assert_eq!(snapshot.generation, 1);

        let mut later_key = original.clone();
        later_key.attachment_id = [12; 16];
        assert!(snapshot.upsert(later_key).unwrap());
        assert_eq!(snapshot.generation, 2);

        let mut replacement = original;
        replacement.assignment.desired_generation = 2;
        replacement.assignment.assignment_digest = [13; 32];
        assert!(snapshot.upsert(replacement.clone()).unwrap());
        assert_eq!(snapshot.generation, 3);
        assert_eq!(snapshot.entries.len(), 2);
        assert_eq!(snapshot.entries[0], replacement);
        snapshot.validate().unwrap();
    }
}
