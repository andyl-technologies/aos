//! Assignment-bound descriptor catalog for mount resources.
//!
//! A root-owned publisher atomically replaces `catalog.json` and bind-pins all
//! referenced sources, namespaces, roots, and destination slots beneath the
//! same private catalog directory. The broker reads one bounded snapshot,
//! matches the complete semantic tuple, then opens every object with `openat2`
//! below its pre-opened root. Callers never supply a host path or descriptor.

use std::collections::BTreeMap;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;
use std::path::PathBuf;

use aos_sandbox_core::{ObjectDescriptor, ObjectDigest};
use aos_sandbox_linux::path::{BeneathRoot, FileIdentity, ResolveOptions, ResolvedPath};
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceIdentity, NamespaceKind};
use aos_sandbox_protocol::{ValidatedAssignmentFence, ValidatedMountRequest};
use serde::{Deserialize, Serialize};

use crate::authorization::semantics_v1::MountCatalogCommitmentV1;
use crate::host_scope::ObservedMountScope;
use crate::{MountError, Result};

const CATALOG_FILE: &str = "catalog.json";
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
    assignment_epoch: u64,
    desired_generation: u64,
    assignment_digest: [u8; 32],
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
    attachment_generation: u64,
    source_path: String,
    mount_namespace_path: String,
    user_namespace_path: String,
    target_root_path: String,
    target_slot_path: String,
    target_relative_path: String,
    source_identity: FileIdentityWire,
    mount_namespace_identity: NamespaceIdentityWire,
    user_namespace_identity: NamespaceIdentityWire,
    target_root_identity: FileIdentityWire,
    target_slot_identity: FileIdentityWire,
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

#[derive(Debug, Deserialize, Serialize)]
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

        let resources = self.catalog.resolve_prepared(request, &scope, binding)?;
        let commitment = resources.authorization_commitment.digest();
        self.prepared
            .insert(key, PreparedNamespace { binding, scope });
        Ok(commitment)
    }
}

impl FileMountCatalog {
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
        2,
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
        b"AOSMCAT2",
        3,
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
    bytes.extend_from_slice(&entry.attachment_generation.to_be_bytes());
    bytes.extend_from_slice(&media_length.to_be_bytes());
    bytes.extend_from_slice(media_type);
    bytes.extend_from_slice(entry.view_revision.digest().as_bytes());
    bytes.extend_from_slice(&entry.view_revision.encoded_size().to_be_bytes());
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
        assignment_epoch: request.fence().assignment_epoch(),
        desired_generation: request.fence().desired_generation(),
        assignment_digest: *request.fence().assignment_digest(),
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
            || self.attachment_generation == 0
        {
            return Err(MountError::State(
                "mount catalog entry contains a sentinel".to_owned(),
            ));
        }
        for path in [
            &self.source_path,
            &self.mount_namespace_path,
            &self.user_namespace_path,
            &self.target_root_path,
            &self.target_slot_path,
            &self.target_relative_path,
        ] {
            validate_relative(path)?;
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
            && self.attachment_generation == request.attachment_generation()
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

    use aos_sandbox_linux::path::FileType;

    use super::*;

    #[test]
    fn catalog_paths_reject_traversal_and_noncanonical_forms() {
        assert!(validate_relative("resources/source").is_ok());
        for invalid in ["", "/absolute", "../escape", "a/../b", "a//b", "./a"] {
            assert!(validate_relative(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn snapshot_and_authorization_commitments_bind_all_behavior_facts() {
        let descriptor = ObjectDescriptor::new(
            aos_sandbox_core::MediaType::new("application/vnd.aos.sandbox.view.v1+cbor".to_owned())
                .unwrap(),
            aos_sandbox_core::ObjectDigest::from_bytes([7; 32]),
            10,
        );
        let entry = MountCatalogEntry {
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
            attachment_generation: 1,
            source_path: "pins/source".to_owned(),
            mount_namespace_path: "pins/mntns".to_owned(),
            user_namespace_path: "pins/userns".to_owned(),
            target_root_path: "pins/root".to_owned(),
            target_slot_path: "pins/slot".to_owned(),
            target_relative_path: "run/aos/attachments/slot".to_owned(),
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
        changed_attachment_generation.attachment_generation += 1;
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
        let snapshot = MountCatalogSnapshot {
            generation: 1,
            entries: vec![entry.clone(), entry],
        };
        assert!(snapshot.validate().is_err());
    }
}
