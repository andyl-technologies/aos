//! Assignment-bound descriptor catalog for mount resources.
//!
//! A root-owned source materializer bind-pins presented view directories at
//! paths derived from portable identities. During Host-backed preparation,
//! Mount verifies that source, the retained Host root and namespaces, and its
//! broker-owned destination slot, then atomically publishes `catalog.json`.
//! Existing static snapshots remain readable for recovery tests. The broker
//! matches the complete semantic tuple and opens every persistent object below
//! its pre-opened root; callers never supply a host path or descriptor.

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;
use std::path::PathBuf;

use aos_proto::aos::sandbox::local::v1::MountSourceConsistency;
use aos_sandbox_core::{ObjectDescriptor, ObjectDigest};
use aos_sandbox_linux::path::{BeneathRoot, FileIdentity, ResolveOptions, ResolvedPath};
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceIdentity, NamespaceKind};
use aos_sandbox_protocol::{ValidatedAssignmentFence, ValidatedMountRequest};
use serde::{Deserialize, Serialize};

use crate::authorization::semantics_v1::MountCatalogCommitmentV1;
use crate::destination_slot::catalog_relative_path as destination_slot_catalog_path;
use crate::host_scope::ObservedMountScope;
use crate::{MountError, Result};

const CATALOG_FILE: &str = "catalog.json";
const CATALOG_NEXT_FILE: &str = "catalog.next";
const MAXIMUM_CATALOG_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_ENTRIES: usize = 16_384;
const MAXIMUM_RELATIVE_PATH_BYTES: usize = 4096;
const MAXIMUM_PREPARED_NAMESPACES: usize = 1_024;

/// Contains the descriptors pinned for one exact mount operation generation.
#[derive(Debug)]
pub struct ResolvedMountResources {
    /// Pinned source directory used to create a detached mount.
    pub source: ResolvedPath,
    /// Pinned payload mount namespace used only by the helper.
    pub mount_namespace: NamespaceFd,
    /// Pinned payload user namespace used for the mount idmap.
    pub user_namespace: NamespaceFd,
    /// Pinned payload root used for helper path hygiene and verification.
    pub target_root: ResolvedPath,
    /// Pinned broker-owned destination slot.
    pub target_slot: ResolvedPath,
    /// Catalog-selected path to the slot beneath `target_root`.
    pub target_relative_path: PathBuf,
    /// Non-circular commitment to the exact verified catalog behavior facts.
    pub(crate) authorization_commitment: MountCatalogCommitmentV1,
}

/// Resolves one validated semantic request into exact pinned kernel objects.
pub trait MountCatalog {
    /// Resolves and verifies all resources from one atomic catalog snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown, stale, mismatched, replaced, incorrectly
    /// typed, or path-unsafe catalog resources.
    fn resolve(&self, request: &ValidatedMountRequest) -> Result<ResolvedMountResources>;

    /// Retains one authenticated Host scope and resolves its catalog commitment.
    ///
    /// The default rejects preparation for catalogs that deliberately use only
    /// static test or recovery pins.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported preparation or an invalid, conflicting,
    /// expired, or unresolvable Host scope.
    fn prepare(
        &mut self,
        _request: &ValidatedMountRequest,
        _scope: ObservedMountScope,
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
    attachment_lease_id: [u8; 16],
    attachment_lease_issued_seconds: i64,
    attachment_lease_expires_seconds: i64,
    source_path: String,
    mount_namespace_path: String,
    user_namespace_path: String,
    target_root_path: String,
    target_slot_path: String,
    target_relative_path: String,
    #[serde(default)]
    prepared_scope: bool,
    #[serde(default)]
    runtime_handle: Option<[u8; 32]>,
    #[serde(default)]
    payload_scope_handle: Option<[u8; 32]>,
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

/// Reads an atomically published catalog beneath a pre-opened private root.
#[derive(Debug)]
pub struct FileMountCatalog {
    root: BeneathRoot,
}

/// Combines the protected file catalog with short-lived Host scope custody.
///
/// One namespace generation can be refreshed only with the same exact Host
/// binding. A changed root, namespace, runtime, or payload-scope handle requires
/// a new signed namespace generation rather than silently replacing authority.
pub struct PreparedMountCatalog {
    catalog: FileMountCatalog,
    prepared: BTreeMap<PreparedNamespaceKey, PreparedNamespace>,
}

impl PreparedMountCatalog {
    /// Constructs an empty bounded preparation registry over a protected catalog.
    #[must_use]
    pub fn new(catalog: FileMountCatalog) -> Self {
        Self {
            catalog,
            prepared: BTreeMap::new(),
        }
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

impl MountCatalog for FileMountCatalog {
    fn resolve(&self, request: &ValidatedMountRequest) -> Result<ResolvedMountResources> {
        self.resolve_static(request)
    }
}

impl MountCatalog for PreparedMountCatalog {
    fn resolve(&self, request: &ValidatedMountRequest) -> Result<ResolvedMountResources> {
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
        self.catalog
            .resolve_prepared(request, &prepared.scope, prepared.binding)
    }

    fn prepare(
        &mut self,
        request: &ValidatedMountRequest,
        scope: ObservedMountScope,
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

        let resources = if self.catalog.contains_matching_entry(request)? {
            self.catalog.resolve_prepared(request, &scope, binding)?
        } else {
            self.catalog.publish_prepared(request, &scope, binding)?
        };
        let commitment = resources.authorization_commitment.digest();
        self.prepared
            .insert(key, PreparedNamespace { binding, scope });
        Ok(commitment)
    }
}

impl FileMountCatalog {
    fn contains_matching_entry(&self, request: &ValidatedMountRequest) -> Result<bool> {
        Ok(self
            .snapshot_or_empty()?
            .entries
            .iter()
            .any(|entry| entry.matches(request)))
    }

    fn publish_prepared(
        &self,
        request: &ValidatedMountRequest,
        scope: &ObservedMountScope,
        binding: PreparedScopeBinding,
    ) -> Result<ResolvedMountResources> {
        let mut snapshot = self.snapshot_or_empty()?;
        let entry = self.prepared_entry(request, scope, &snapshot)?;
        if !snapshot.upsert(entry)? {
            return self.resolve_prepared(request, scope, binding);
        }
        self.publish_snapshot(&snapshot)?;

        let published = self.snapshot()?;
        if published != snapshot {
            return Err(MountError::State(
                "mount catalog publication did not reproduce its exact snapshot".to_owned(),
            ));
        }
        self.resolve_prepared(request, scope, binding)
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
                    || (entry.prepared_scope
                        && (entry.runtime_handle != Some(*scope.metadata().runtime_handle())
                            || entry.payload_scope_handle
                                != Some(*scope.metadata().payload_scope_handle()))))
        }) {
            return Err(MountError::Fence(
                "namespace generation cannot replace its catalogued Host scope",
            ));
        }

        let prior = snapshot.entries.iter().find(|entry| {
            entry.assignment.incarnation_id == *request.fence().incarnation_id()
                && entry.attachment_id == *request.attachment_id()
        });
        let (view_revision, source_path) = match request.view_revision() {
            Some(revision) => (revision.clone(), source_catalog_relative_path(request)?),
            None => {
                let prior = prior
                    .filter(|entry| entry.matches_source(request))
                    .ok_or_else(|| {
                        MountError::Worker(
                            "mount catalog cannot recover an omitted source recipe".to_owned(),
                        )
                    })?;
                (
                    prior.view_revision.clone(),
                    PathBuf::from(&prior.source_path),
                )
            }
        };
        let source = resolve_directory(&self.root, path_text(&source_path)?)?;
        let target_slot_path = destination_slot_catalog_path(
            request.fence().sandbox_id(),
            request.fence().incarnation_id(),
            request.namespace_generation(),
            request.destination_slot_id(),
        );
        let pinned_target_slot = resolve_directory(&self.root, path_text(&target_slot_path)?)?;
        let target_relative_path = payload_slot_relative_path(request.destination_slot_id());
        let target_slot = scope
            .root()
            .resolve(
                &target_relative_path,
                ResolveOptions {
                    no_mount_crossing: false,
                    require_directory: true,
                },
            )
            .map_err(|error| MountError::Worker(error.to_string()))?;
        if target_slot.identity() != pinned_target_slot.identity() {
            return Err(MountError::Worker(
                "Host-root destination slot differs from its broker-owned pin".to_owned(),
            ));
        }

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
            attachment_lease_id: *request.attachment_lease_id(),
            attachment_lease_issued_seconds: request.attachment_lease_issued_seconds(),
            attachment_lease_expires_seconds: request.attachment_lease_expires_seconds(),
            source_path: path_text(&source_path)?.to_owned(),
            mount_namespace_path: String::new(),
            user_namespace_path: String::new(),
            target_root_path: String::new(),
            target_slot_path: path_text(&target_slot_path)?.to_owned(),
            target_relative_path: path_text(&target_relative_path)?.to_owned(),
            prepared_scope: true,
            runtime_handle: Some(*scope.metadata().runtime_handle()),
            payload_scope_handle: Some(*scope.metadata().payload_scope_handle()),
            source_identity: FileIdentityWire::from(source.identity()),
            mount_namespace_identity,
            user_namespace_identity,
            target_root_identity: root_identity,
            target_slot_identity: FileIdentityWire::from(target_slot.identity()),
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

    fn matching_entry(&self, request: &ValidatedMountRequest) -> Result<(u64, MountCatalogEntry)> {
        let snapshot = self.snapshot()?;
        let entry = snapshot
            .entries
            .iter()
            .find(|entry| entry.matches(request))
            .cloned()
            .ok_or_else(|| MountError::Worker("mount catalog tuple is unavailable".to_owned()))?;
        Ok((snapshot.generation, entry))
    }

    fn resolve_static(&self, request: &ValidatedMountRequest) -> Result<ResolvedMountResources> {
        let (generation, entry) = self.matching_entry(request)?;
        if entry.prepared_scope {
            return Err(MountError::Worker(
                "Host-prepared catalog entry requires retained scope custody".to_owned(),
            ));
        }

        let source = resolve_directory(&self.root, &entry.source_path)?;
        verify_file(source.identity(), entry.source_identity, "source")?;
        let mount_namespace = self
            .root
            .open_namespace(Path::new(&entry.mount_namespace_path), NamespaceKind::Mount)
            .map_err(|error| MountError::Worker(error.to_string()))?;
        verify_namespace(
            mount_namespace.identity(),
            entry.mount_namespace_identity,
            "mount namespace",
        )?;
        let user_namespace = self
            .root
            .open_namespace(Path::new(&entry.user_namespace_path), NamespaceKind::User)
            .map_err(|error| MountError::Worker(error.to_string()))?;
        verify_namespace(
            user_namespace.identity(),
            entry.user_namespace_identity,
            "user namespace",
        )?;
        let target_root = resolve_directory(&self.root, &entry.target_root_path)?;
        verify_file(
            target_root.identity(),
            entry.target_root_identity,
            "target root",
        )?;
        let target_slot = resolve_directory(&self.root, &entry.target_slot_path)?;
        verify_file(
            target_slot.identity(),
            entry.target_slot_identity,
            "target slot",
        )?;
        let authorization_commitment = catalog_authorization_commitment(
            generation,
            &entry,
            source.identity(),
            mount_namespace.identity(),
            user_namespace.identity(),
            target_root.identity(),
            target_slot.identity(),
        )?;

        Ok(ResolvedMountResources {
            source,
            mount_namespace,
            user_namespace,
            target_root,
            target_slot,
            target_relative_path: PathBuf::from(&entry.target_relative_path),
            authorization_commitment,
        })
    }

    fn resolve_prepared(
        &self,
        request: &ValidatedMountRequest,
        scope: &ObservedMountScope,
        binding: PreparedScopeBinding,
    ) -> Result<ResolvedMountResources> {
        let (generation, entry) = self.matching_entry(request)?;
        if entry.prepared_scope
            && (entry.runtime_handle != Some(binding.runtime_handle)
                || entry.payload_scope_handle != Some(binding.payload_scope_handle))
        {
            return Err(MountError::Fence(
                "catalogued Host scope handles changed under one namespace generation",
            ));
        }
        let source = resolve_directory(&self.root, &entry.source_path)?;
        verify_file(source.identity(), entry.source_identity, "source")?;

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

        let pinned_target_slot = resolve_directory(&self.root, &entry.target_slot_path)?;
        verify_file(
            pinned_target_slot.identity(),
            entry.target_slot_identity,
            "target slot pin",
        )?;
        let target_slot = scope
            .root()
            .resolve(
                Path::new(&entry.target_relative_path),
                ResolveOptions {
                    no_mount_crossing: false,
                    require_directory: true,
                },
            )
            .map_err(|error| MountError::Worker(error.to_string()))?;
        verify_file(
            target_slot.identity(),
            entry.target_slot_identity,
            "target slot",
        )?;
        if target_slot.identity() != pinned_target_slot.identity() {
            return Err(MountError::Worker(
                "Host-root target slot differs from its protected catalog pin".to_owned(),
            ));
        }

        let authorization_commitment = prepared_catalog_authorization_commitment(
            generation,
            &entry,
            binding,
            source.identity(),
            target_slot.identity(),
        )?;
        Ok(ResolvedMountResources {
            source,
            mount_namespace,
            user_namespace,
            target_root,
            target_slot,
            target_relative_path: PathBuf::from(&entry.target_relative_path),
            authorization_commitment,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn catalog_authorization_commitment(
    generation: u64,
    entry: &MountCatalogEntry,
    source: FileIdentity,
    mount_namespace: NamespaceIdentity,
    user_namespace: NamespaceIdentity,
    target_root: FileIdentity,
    target_slot: FileIdentity,
) -> Result<MountCatalogCommitmentV1> {
    let bytes = catalog_authorization_bytes(
        b"AOSMCAT1",
        4,
        generation,
        entry,
        &[],
        source,
        mount_namespace,
        user_namespace,
        target_root,
        target_slot,
    )?;
    MountCatalogCommitmentV1::for_verified_canonical_bytes(&bytes)
        .map_err(|error| MountError::State(error.to_string()))
}

fn prepared_catalog_authorization_commitment(
    generation: u64,
    entry: &MountCatalogEntry,
    binding: PreparedScopeBinding,
    source: FileIdentity,
    target_slot: FileIdentity,
) -> Result<MountCatalogCommitmentV1> {
    let mut host_binding = Vec::with_capacity(64);
    host_binding.extend_from_slice(&binding.runtime_handle);
    host_binding.extend_from_slice(&binding.payload_scope_handle);
    let bytes = catalog_authorization_bytes(
        b"AOSMCAT3",
        5,
        generation,
        entry,
        &host_binding,
        source,
        binding.mount_namespace,
        binding.user_namespace,
        binding.root,
        target_slot,
    )?;
    MountCatalogCommitmentV1::for_verified_canonical_bytes(&bytes)
        .map_err(|error| MountError::State(error.to_string()))
}

#[allow(clippy::too_many_arguments)]
fn catalog_authorization_bytes(
    magic: &[u8; 8],
    version: u16,
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
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&version.to_be_bytes());
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
        let key = (entry.assignment.incarnation_id, entry.attachment_id);
        match self.entries.binary_search_by_key(&key, |candidate| {
            (candidate.assignment.incarnation_id, candidate.attachment_id)
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
            let key = (entry.assignment.incarnation_id, entry.attachment_id);
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
            || self.attachment_lease_id == [0; 16]
            || self.attachment_lease_expires_seconds <= self.attachment_lease_issued_seconds
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
        for path in [
            &self.source_path,
            &self.target_slot_path,
            &self.target_relative_path,
        ] {
            validate_relative(path)?;
        }
        if self.prepared_scope {
            if !self.mount_namespace_path.is_empty()
                || !self.user_namespace_path.is_empty()
                || !self.target_root_path.is_empty()
                || self.runtime_handle.is_none_or(|handle| handle == [0; 32])
                || self
                    .payload_scope_handle
                    .is_none_or(|handle| handle == [0; 32])
            {
                return Err(MountError::State(
                    "Host-prepared catalog entry contains invalid scope binding".to_owned(),
                ));
            }
        } else {
            if self.runtime_handle.is_some() || self.payload_scope_handle.is_some() {
                return Err(MountError::State(
                    "static catalog entry contains Host scope handles".to_owned(),
                ));
            }
            for path in [
                &self.mount_namespace_path,
                &self.user_namespace_path,
                &self.target_root_path,
            ] {
                validate_relative(path)?;
            }
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
        self.assignment.sandbox_id == *fence.sandbox_id()
            && self.assignment.incarnation_id == *fence.incarnation_id()
            && self.assignment.assignment_epoch == fence.assignment_epoch()
            && self.assignment.desired_generation == fence.desired_generation()
            && self.assignment.assignment_digest == *fence.assignment_digest()
            && self.attachment_id == *request.attachment_id()
            && self.destination_slot_id == *request.destination_slot_id()
            && request
                .view_revision()
                .is_none_or(|revision| revision == &self.view_revision)
            && self.source_generation == request.source_generation()
            && self.namespace_generation == request.namespace_generation()
            && self.desired_attachment_generation == request.desired_attachment_generation()
            && self.resource_attachment_generation == request.resource_attachment_generation()
            && self.source_view_id == *request.source_view_id()
            && self.source_incarnation_id.as_ref() == request.source_incarnation_id()
            && self.source_consistency.protocol_value() == request.source_consistency()
            && self.attachment_lease_id == *request.attachment_lease_id()
            && self.attachment_lease_issued_seconds == request.attachment_lease_issued_seconds()
            && self.attachment_lease_expires_seconds == request.attachment_lease_expires_seconds()
    }

    fn matches_source(&self, request: &ValidatedMountRequest) -> bool {
        self.source_generation == request.source_generation()
            && self.source_view_id == *request.source_view_id()
            && self.source_incarnation_id.as_ref() == request.source_incarnation_id()
            && self.source_consistency.protocol_value() == request.source_consistency()
    }
}

fn resolve_directory(root: &BeneathRoot, path: &str) -> Result<ResolvedPath> {
    root.resolve(
        Path::new(path),
        ResolveOptions {
            no_mount_crossing: false,
            require_directory: true,
        },
    )
    .map_err(|error| MountError::Worker(error.to_string()))
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

/// Derives the broker-private source pin for one exact Mount recipe.
///
/// The path contains only canonical portable identities. A source materializer
/// must populate this location before Mount catalog preparation; callers cannot
/// nominate another path through the protocol.
///
/// # Errors
///
/// Returns an error when the validated request carries no view revision or its
/// source consistency unexpectedly lacks or includes a live incarnation.
pub fn source_catalog_relative_path(request: &ValidatedMountRequest) -> Result<PathBuf> {
    let revision = request.view_revision().ok_or_else(|| {
        MountError::Worker("mount source pin requires an exact view revision".to_owned())
    })?;
    let source_scope = match (
        request.source_consistency(),
        request.source_incarnation_id(),
    ) {
        (MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION, None) => {
            "immutable".to_owned()
        }
        (MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE, Some(incarnation)) => {
            encode_hex(incarnation)
        }
        (MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA, None) => {
            "replica".to_owned()
        }
        _ => {
            return Err(MountError::State(
                "validated Mount source scope is inconsistent".to_owned(),
            ));
        }
    };

    Ok(Path::new("sources")
        .join(encode_hex(request.source_view_id()))
        .join(format!("{:016x}", request.source_generation()))
        .join(source_scope)
        .join(encode_hex(revision.digest().as_bytes())))
}

fn payload_slot_relative_path(slot_id: &[u8; 16]) -> PathBuf {
    Path::new("run")
        .join("aos")
        .join("attachments")
        .join(encode_hex(slot_id))
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

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
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
        ApplyMountRequest, AssignmentFence, Audience, Descriptor, MountAction, MountAttributes,
        RequestHeader,
    };
    use aos_sandbox_linux::path::FileType;
    use aos_sandbox_protocol::{PeerCredentials, PeerPolicy, decode_mount_request};
    use buffa::Message as _;

    use super::*;

    fn catalog_entry() -> MountCatalogEntry {
        let descriptor = ObjectDescriptor::new(
            aos_sandbox_core::MediaType::new("application/vnd.aos.sandbox.view.v1+cbor".to_owned())
                .unwrap(),
            aos_sandbox_core::ObjectDigest::from_bytes([7; 32]),
            10,
        );

        MountCatalogEntry {
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
            attachment_lease_id: [8; 16],
            attachment_lease_issued_seconds: 9,
            attachment_lease_expires_seconds: 10,
            source_path: "pins/source".to_owned(),
            mount_namespace_path: "pins/mntns".to_owned(),
            user_namespace_path: "pins/userns".to_owned(),
            target_root_path: "pins/root".to_owned(),
            target_slot_path: destination_slot_catalog_path(&[1; 16], &[2; 16], 1, &[5; 16])
                .to_string_lossy()
                .into_owned(),
            target_relative_path: "run/aos/attachments/slot".to_owned(),
            prepared_scope: false,
            runtime_handle: None,
            payload_scope_handle: None,
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
        }
    }

    fn validated_request(
        consistency: MountSourceConsistency,
        source_incarnation_id: Option<[u8; 16]>,
    ) -> ValidatedMountRequest {
        let request = ApplyMountRequest {
            header: Some(RequestHeader {
                protocol_major: 1,
                protocol_minor: 2,
                request_id: vec![11; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 1_000,
                maximum_response_bytes: 4096,
                ..Default::default()
            })
            .into(),
            fence: Some(AssignmentFence {
                sandbox_id: vec![1; 16],
                incarnation_id: vec![2; 16],
                assignment_epoch: 1,
                desired_generation: 1,
                assignment_digest: vec![3; 32],
                ..Default::default()
            })
            .into(),
            action: MountAction::MOUNT_ACTION_CREATE_DETACHED.into(),
            attachment_id: vec![4; 16],
            destination_slot_id: vec![5; 16],
            view_revision: Some(Descriptor {
                media_type: "application/vnd.aos.sandbox.view.v1+cbor".to_owned(),
                sha256: vec![6; 32],
                encoded_size: 64,
                ..Default::default()
            })
            .into(),
            attributes: Some(MountAttributes {
                read_only: true,
                no_exec: true,
                no_suid: true,
                no_device: true,
                no_atime: true,
                ..Default::default()
            })
            .into(),
            source_generation: 7,
            namespace_generation: 1,
            desired_attachment_generation: 1,
            resource_attachment_generation: 1,
            source_view_id: vec![8; 16],
            source_incarnation_id: source_incarnation_id.map_or_else(Vec::new, |id| id.to_vec()),
            source_consistency: consistency.into(),
            attachment_lease_id: vec![9; 16],
            attachment_lease_issued_seconds: 10,
            attachment_lease_expires_seconds: 20,
            ..Default::default()
        };
        decode_mount_request(
            &request.encode_to_vec(),
            PeerCredentials {
                uid: 811,
                gid: 811,
                pid: Some(42),
            },
            PeerPolicy {
                uid: 811,
                gid: Some(811),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            1,
        )
        .unwrap()
    }

    #[test]
    fn catalog_paths_reject_traversal_and_noncanonical_forms() {
        assert!(validate_relative("resources/source").is_ok());
        for invalid in ["", "/absolute", "../escape", "a/../b", "a//b", "./a"] {
            assert!(validate_relative(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn source_pin_paths_are_derived_from_the_exact_portable_recipe() {
        let immutable = validated_request(
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION,
            None,
        );
        assert_eq!(
            source_catalog_relative_path(&immutable).unwrap(),
            Path::new("sources")
                .join("08080808080808080808080808080808")
                .join("0000000000000007")
                .join("immutable")
                .join("0606060606060606060606060606060606060606060606060606060606060606")
        );

        let live = validated_request(
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE,
            Some([10; 16]),
        );
        assert_eq!(
            source_catalog_relative_path(&live)
                .unwrap()
                .components()
                .nth(3),
            Some(std::path::Component::Normal(std::ffi::OsStr::new(
                "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
            )))
        );
    }

    #[test]
    fn snapshot_and_authorization_commitments_bind_all_behavior_facts() {
        let entry = catalog_entry();
        assert!(entry.validate().is_ok());
        let mut redirected_slot = entry.clone();
        redirected_slot.target_slot_path = "pins/slot".to_owned();
        assert!(redirected_slot.validate().is_err());

        let directory = |device, inode| FileIdentity {
            device,
            inode,
            file_type: FileType::Directory,
        };
        let namespace = |device, inode| NamespaceIdentity { device, inode };
        let commitment = catalog_authorization_commitment(
            1,
            &entry,
            directory(1, 1),
            namespace(1, 2),
            namespace(1, 3),
            directory(1, 4),
            directory(1, 5),
        )
        .unwrap();
        assert_ne!(
            catalog_authorization_commitment(
                2,
                &entry,
                directory(1, 1),
                namespace(1, 2),
                namespace(1, 3),
                directory(1, 4),
                directory(1, 5),
            )
            .unwrap(),
            commitment
        );
        let mut changed_path = entry.clone();
        changed_path.target_relative_path = "run/aos/attachments/other".to_owned();
        assert_ne!(
            catalog_authorization_commitment(
                1,
                &changed_path,
                directory(1, 1),
                namespace(1, 2),
                namespace(1, 3),
                directory(1, 4),
                directory(1, 5),
            )
            .unwrap(),
            commitment
        );
        let mut changed_attachment_generation = entry.clone();
        changed_attachment_generation.desired_attachment_generation += 1;
        assert_ne!(
            catalog_authorization_commitment(
                1,
                &changed_attachment_generation,
                directory(1, 1),
                namespace(1, 2),
                namespace(1, 3),
                directory(1, 4),
                directory(1, 5),
            )
            .unwrap(),
            commitment
        );
        let mut changed_resource_generation = entry.clone();
        changed_resource_generation.resource_attachment_generation += 1;
        assert_ne!(
            catalog_authorization_commitment(
                1,
                &changed_resource_generation,
                directory(1, 1),
                namespace(1, 2),
                namespace(1, 3),
                directory(1, 4),
                directory(1, 5),
            )
            .unwrap(),
            commitment
        );
        let mut changed_source = entry.clone();
        changed_source.source_view_id = [11; 16];
        assert_ne!(
            catalog_authorization_commitment(
                1,
                &changed_source,
                directory(1, 1),
                namespace(1, 2),
                namespace(1, 3),
                directory(1, 4),
                directory(1, 5),
            )
            .unwrap(),
            commitment
        );
        let mut changed_lease = entry.clone();
        changed_lease.attachment_lease_id = [12; 16];
        assert_ne!(
            catalog_authorization_commitment(
                1,
                &changed_lease,
                directory(1, 1),
                namespace(1, 2),
                namespace(1, 3),
                directory(1, 4),
                directory(1, 5),
            )
            .unwrap(),
            commitment
        );
        assert_ne!(
            catalog_authorization_commitment(
                1,
                &entry,
                directory(9, 9),
                namespace(1, 2),
                namespace(1, 3),
                directory(1, 4),
                directory(1, 5),
            )
            .unwrap(),
            commitment
        );
        let mut local_live = entry.clone();
        local_live.source_consistency = CatalogSourceConsistency::LocalLive;
        assert!(local_live.validate().is_err());
        local_live.source_incarnation_id = Some([13; 16]);
        local_live.validate().unwrap();

        let mut extraneous_incarnation = entry.clone();
        extraneous_incarnation.source_incarnation_id = Some([13; 16]);
        assert!(extraneous_incarnation.validate().is_err());

        let snapshot = MountCatalogSnapshot {
            generation: 1,
            entries: vec![entry.clone(), entry],
        };
        assert!(snapshot.validate().is_err());
    }

    #[test]
    fn host_prepared_entries_exclude_reopenable_scope_paths() {
        let mut entry = catalog_entry();
        entry.prepared_scope = true;
        assert!(entry.validate().is_err());

        entry.mount_namespace_path.clear();
        entry.user_namespace_path.clear();
        entry.target_root_path.clear();
        entry.runtime_handle = Some([14; 32]);
        entry.payload_scope_handle = Some([15; 32]);
        entry.validate().unwrap();

        let mut static_entry = entry;
        static_entry.prepared_scope = false;
        assert!(static_entry.validate().is_err());
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
