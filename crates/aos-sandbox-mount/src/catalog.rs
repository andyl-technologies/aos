//! Assignment-bound descriptor catalog for mount resources.
//!
//! A root-owned publisher atomically replaces `catalog.json` and bind-pins all
//! referenced sources, namespaces, roots, and destination slots beneath the
//! same private catalog directory. The broker reads one bounded snapshot,
//! matches the complete semantic tuple, then opens every object with `openat2`
//! below its pre-opened root. Callers never supply a host path or descriptor.

use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use aos_sandbox_core::ObjectDescriptor;
use aos_sandbox_linux::path::{BeneathRoot, FileIdentity, ResolveOptions, ResolvedPath};
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceIdentity, NamespaceKind};
use aos_sandbox_protocol::{ValidatedAssignmentFence, ValidatedMountRequest};
use serde::{Deserialize, Serialize};

use crate::{MountError, Result};

const CATALOG_FILE: &str = "catalog.json";
const MAXIMUM_CATALOG_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_ENTRIES: usize = 16_384;
const MAXIMUM_RELATIVE_PATH_BYTES: usize = 4096;

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
    source_path: String,
    mount_namespace_path: String,
    user_namespace_path: String,
    target_root_path: String,
    target_slot_path: String,
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
        let snapshot = self.snapshot()?;
        let entry = snapshot
            .entries
            .iter()
            .find(|entry| entry.matches(request))
            .ok_or_else(|| MountError::Worker("mount catalog tuple is unavailable".to_owned()))?;

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

        Ok(ResolvedMountResources {
            source,
            mount_namespace,
            user_namespace,
            target_root,
            target_slot,
        })
    }
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
            && request.view_revision() == Some(&self.view_revision)
            && self.source_generation == request.source_generation()
            && self.namespace_generation == request.namespace_generation()
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

    use super::*;

    #[test]
    fn catalog_paths_reject_traversal_and_noncanonical_forms() {
        assert!(validate_relative("resources/source").is_ok());
        for invalid in ["", "/absolute", "../escape", "a/../b", "a//b", "./a"] {
            assert!(validate_relative(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn snapshot_rejects_duplicate_semantic_keys_before_opening_resources() {
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
            source_path: "pins/source".to_owned(),
            mount_namespace_path: "pins/mntns".to_owned(),
            user_namespace_path: "pins/userns".to_owned(),
            target_root_path: "pins/root".to_owned(),
            target_slot_path: "pins/slot".to_owned(),
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
        let snapshot = MountCatalogSnapshot {
            generation: 1,
            entries: vec![entry.clone(), entry],
        };
        assert!(snapshot.validate().is_err());
    }
}
