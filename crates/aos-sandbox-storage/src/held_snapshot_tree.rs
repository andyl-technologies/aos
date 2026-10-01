//! Bounded physical measurement of the portable subset of a held snapshot.
//!
//! The input is an already-pinned snapshot root descriptor, not a pathname.
//! Every descendant is resolved beneath that root without following symlinks
//! or crossing mounts. Unsupported portable state closes measurement; this
//! module neither acquires the root nor signs an AOSPCZ01 receipt.
//!
//! The identity digest hashes a domain tag followed by each accepted inode in
//! sorted depth-first order. Every node contributes its kind, length-prefixed
//! root-relative byte path, portable UID, GID, and low twelve mode bits.
//! Unsupported identity-bearing xattrs, symlinks, and hardlinks close the walk.
//!
//! For a root `(d, "", UID 0, GID 0, mode 0755)` containing one file
//! `(f, "payload", UID 42, GID 43, mode 0644)`, the preimage starts with
//! `b"aos.sandbox.storage.held-snapshot-identity-tree.v1\0"`, then these
//! two node records:
//!
//! ```text
//! 64 00000000 00000000 00000000 01ed
//! 66 00000007 7061796c6f6164 0000002a 0000002b 01a4
//! SHA-256 d96f62fc5f9c09ace8b0e2ce8ec2d746df8aeee6d0d0661c7019a9e2924f76b7
//! ```

use std::ffi::OsString;
use std::io::Read as _;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::Path;

use aos_sandbox_core::format::{encode_directory, encode_tree};
use aos_sandbox_core::model::tree::{
    ContentLayout, Directory, DirectoryEntry, FileNode, FilesystemMetadata, Node, Tree,
};
use aos_sandbox_core::{
    MediaType, ObjectDescriptor, ObjectDigest, PathName, PortableMediaType, descriptor_for_bytes,
};
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::mount::{
    DetachedMount, FileSystemContext, MountAttributes, filesystem_uuid,
};
use aos_sandbox_linux::path::{BeneathRoot, FileType, ResolveOptions};
use aos_sandbox_source_provider_protocol::held_snapshot_content_digest_v1;
use rustix::fs::{Mode, OFlags, SeekFrom, Stat, StatVfsMountFlags};
use sha2::{Digest as _, Sha256};

use crate::process::original_cutoff::WorkerOriginalCheckedViewV3;
use crate::root_policy::PortableRootAttributesV1;

const MAXIMUM_DEPTH: usize = 64;
const MAXIMUM_NODES: usize = 4096;
const MAXIMUM_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const IDENTITY_TREE_DOMAIN: &[u8] = b"aos.sandbox.storage.held-snapshot-identity-tree.v1\0";

/// Reports a physical state that cannot establish one exact portable tree.
#[derive(Debug, thiserror::Error)]
pub enum HeldSnapshotTreeErrorV1 {
    /// A kernel or descriptor operation failed closed.
    #[error("held snapshot descriptor read failed: {0}")]
    Linux(#[from] aos_sandbox_linux::Error),
    /// A filesystem observation failed closed.
    #[error("held snapshot filesystem read failed: {0}")]
    Filesystem(#[from] rustix::io::Errno),
    /// A regular file could not be read completely.
    #[error("held snapshot content read failed: {0}")]
    Read(#[from] std::io::Error),
    /// A node, metadata field, or resource demand is outside this measured subset.
    #[error("held snapshot contains unsupported or changed portable state")]
    Unsupported,
    /// The physically measured tree disagrees with the selected commitment.
    #[error("held snapshot content commitment differs from physical bytes")]
    Mismatch,
    /// The mounted ZFS superblock is not the selected pool and snapshot.
    #[error("held snapshot mount GUID differs from protected selection")]
    MountGuidMismatch,
}

/// Retains a physically measured tree identity without any Storage signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MeasuredHeldSnapshotTreeV1 {
    pub(crate) mount_id: MountId,
    pub(crate) root_device: u64,
    pub(crate) root_inode: u64,
    pub(crate) tree: ObjectDescriptor,
    pub(crate) content_digest: ObjectDigest,
    pub(crate) nodes: usize,
    pub(crate) file_bytes: usize,
    pub(crate) identity: HeldSnapshotIdentityObservationV1,
}

/// Describes only identities physically observed in the accepted tree subset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HeldSnapshotIdentityObservationV1 {
    pub(crate) root_attributes: PortableRootAttributesV1,
    pub(crate) maximum_portable_uid: u32,
    pub(crate) maximum_portable_gid: u32,
    pub(crate) distinct_inode_count: u64,
    pub(crate) directory_entry_count: u64,
    pub(crate) identity_tree_digest: ObjectDigest,
}

/// Measures every byte in the supported tree beneath one read-only root FD.
///
/// This does not establish ZFS GUID, hold, journal, or writer-cut currentness.
/// Those remain obligations of the Storage caller that acquired the FD.
///
/// # Errors
///
/// Rejects a writable mount, missing secure mount flags, unsupported nodes or
/// metadata, sparse or linked files, mount crossings, resource-limit excess,
/// changed inode state, and disagreement with the expected AOSPCZ01 digest.
pub(crate) fn measure_read_only_held_snapshot_tree(
    root: OwnedFd,
    expected_content_digest: ObjectDigest,
) -> Result<MeasuredHeldSnapshotTreeV1, HeldSnapshotTreeErrorV1> {
    let measured = measure_secure_root(root)?;
    if measured.content_digest != expected_content_digest {
        return Err(HeldSnapshotTreeErrorV1::Mismatch);
    }
    Ok(measured)
}

fn measure_secure_root(
    root: OwnedFd,
) -> Result<MeasuredHeldSnapshotTreeV1, HeldSnapshotTreeErrorV1> {
    measure_secure_root_for(root, None)
}

fn measure_secure_root_for(
    root: OwnedFd,
    mut original: Option<&mut WorkerOriginalCheckedViewV3<'_>>,
) -> Result<MeasuredHeldSnapshotTreeV1, HeldSnapshotTreeErrorV1> {
    check_original(&mut original)?;
    let mount_id = MountId::from_fd(root.as_fd())?;
    let flags = rustix::fs::fstatvfs(root.as_fd())?.f_flag;
    if !flags.contains(
        StatVfsMountFlags::RDONLY
            | StatVfsMountFlags::NOSUID
            | StatVfsMountFlags::NODEV
            | StatVfsMountFlags::NOEXEC,
    ) {
        return Err(HeldSnapshotTreeErrorV1::Unsupported);
    }

    let root_stat = rustix::fs::fstat(root.as_fd())?;
    let beneath = BeneathRoot::from_owned(root)?;
    let mut walker = PhysicalTreeWalker {
        original,
        ..PhysicalTreeWalker::default()
    };
    let tree = walker.measure_tree(&beneath)?;
    walker.check_original()?;
    let final_stat = rustix::fs::fstat(beneath.as_fd())?;
    if !same_inode_state(&root_stat, &final_stat) || MountId::from_fd(beneath.as_fd())? != mount_id
    {
        return Err(HeldSnapshotTreeErrorV1::Unsupported);
    }
    let content_digest =
        held_snapshot_content_digest_v1(&tree).map_err(|_| HeldSnapshotTreeErrorV1::Unsupported)?;
    let identity = walker.identity_observation()?;
    walker.check_original()?;
    Ok(MeasuredHeldSnapshotTreeV1 {
        mount_id,
        root_device: root_stat.st_dev,
        root_inode: root_stat.st_ino,
        tree,
        content_digest,
        nodes: walker.nodes,
        file_bytes: walker.file_bytes,
        identity,
    })
}

/// Mounts and measures one catalog-selected snapshot without publishing it.
///
/// The caller must hold Storage's journal cut and independently bracket this
/// observation with exact ZFS GUID and hold readback. The returned detached
/// mount never leaves this function or the reader's private mount namespace.
pub(crate) fn measure_detached_snapshot(
    snapshot_name: &str,
) -> Result<MeasuredHeldSnapshotTreeV1, HeldSnapshotTreeErrorV1> {
    let mount = mount_detached_snapshot(snapshot_name)?;
    measure_secure_root(rustix::io::dup(mount.as_fd())?)
}

/// Measures a detached snapshot only when its mounted superblock proves both GUIDs.
///
/// # Errors
///
/// Rejects unsupported UUID ioctl behavior, a different mounted pool or
/// snapshot, changed mount identity, or any unsupported portable tree state.
pub(crate) fn measure_bound_detached_snapshot(
    snapshot_name: &str,
    expected_pool_guid: u64,
    expected_snapshot_guid: u64,
) -> Result<MeasuredHeldSnapshotTreeV1, HeldSnapshotTreeErrorV1> {
    let (measured, _mount) = measure_bound_detached_snapshot_with_mount(
        snapshot_name,
        expected_pool_guid,
        expected_snapshot_guid,
    )?;
    Ok(measured)
}

/// Keeps the exact GUID-verified detached mount alive with its measurement.
///
/// The caller must transfer or drop the mount before its confined reader exits.
/// No receipt or authority is issued by retaining this descriptor.
pub(crate) fn measure_bound_detached_snapshot_with_mount(
    snapshot_name: &str,
    expected_pool_guid: u64,
    expected_snapshot_guid: u64,
) -> Result<(MeasuredHeldSnapshotTreeV1, DetachedMount), HeldSnapshotTreeErrorV1> {
    measure_bound_detached_snapshot_for(
        snapshot_name,
        expected_pool_guid,
        expected_snapshot_guid,
        None,
    )
}

/// Borrows only the already admitted original worker branch, never raw DATA.
pub(crate) fn measure_bound_original_snapshot_with_mount(
    snapshot_name: &str,
    expected_pool_guid: u64,
    expected_snapshot_guid: u64,
    original: &mut WorkerOriginalCheckedViewV3<'_>,
    retained_mount: &mut Option<DetachedMount>,
) -> Result<MeasuredHeldSnapshotTreeV1, HeldSnapshotTreeErrorV1> {
    if expected_pool_guid == 0 || expected_snapshot_guid == 0 || retained_mount.is_some() {
        return Err(HeldSnapshotTreeErrorV1::Unsupported);
    }

    mount_detached_snapshot_into(snapshot_name, Some(original), retained_mount)?;
    let mount = retained_mount
        .as_ref()
        .ok_or(HeldSnapshotTreeErrorV1::Unsupported)?;
    measure_bound_mount_for(
        mount,
        expected_pool_guid,
        expected_snapshot_guid,
        Some(original),
    )
}

fn measure_bound_detached_snapshot_for(
    snapshot_name: &str,
    expected_pool_guid: u64,
    expected_snapshot_guid: u64,
    mut original: Option<&mut WorkerOriginalCheckedViewV3<'_>>,
) -> Result<(MeasuredHeldSnapshotTreeV1, DetachedMount), HeldSnapshotTreeErrorV1> {
    if expected_pool_guid == 0 || expected_snapshot_guid == 0 {
        return Err(HeldSnapshotTreeErrorV1::Unsupported);
    }

    let mount = mount_detached_snapshot_for(snapshot_name, original.as_deref_mut())?;
    let measured = measure_bound_mount_for(
        &mount,
        expected_pool_guid,
        expected_snapshot_guid,
        original,
    )?;
    Ok((measured, mount))
}

fn measure_bound_mount_for(
    mount: &DetachedMount,
    expected_pool_guid: u64,
    expected_snapshot_guid: u64,
    mut original: Option<&mut WorkerOriginalCheckedViewV3<'_>>,
) -> Result<MeasuredHeldSnapshotTreeV1, HeldSnapshotTreeErrorV1> {
    check_original(&mut original)?;
    let readable_root = rustix::fs::openat(
        mount.as_fd(),
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    if MountId::from_fd(readable_root.as_fd())? != mount.mount_id() {
        return Err(HeldSnapshotTreeErrorV1::Unsupported);
    }
    verify_mounted_snapshot_uuid(
        filesystem_uuid(readable_root.as_fd())?,
        expected_pool_guid,
        expected_snapshot_guid,
    )?;

    check_original(&mut original)?;
    let measured = measure_secure_root_for(
        rustix::io::dup(mount.as_fd())?,
        original.as_deref_mut(),
    )?;
    check_original(&mut original)?;
    if measured.mount_id != mount.mount_id()
        || MountId::from_fd(readable_root.as_fd())? != mount.mount_id()
    {
        return Err(HeldSnapshotTreeErrorV1::Unsupported);
    }
    verify_mounted_snapshot_uuid(
        filesystem_uuid(readable_root.as_fd())?,
        expected_pool_guid,
        expected_snapshot_guid,
    )?;
    check_original(&mut original)?;
    Ok(measured)
}

pub(crate) fn verify_mounted_snapshot_uuid(
    uuid: [u8; 16],
    expected_pool_guid: u64,
    expected_snapshot_guid: u64,
) -> Result<(), HeldSnapshotTreeErrorV1> {
    let mut pool_bytes = [0; 8];
    pool_bytes.copy_from_slice(&uuid[..8]);
    let mut snapshot_bytes = [0; 8];
    snapshot_bytes.copy_from_slice(&uuid[8..]);
    let pool = u64::from_be_bytes(pool_bytes);
    let snapshot = u64::from_be_bytes(snapshot_bytes);
    if pool != expected_pool_guid || snapshot != expected_snapshot_guid {
        return Err(HeldSnapshotTreeErrorV1::MountGuidMismatch);
    }
    Ok(())
}

fn mount_detached_snapshot(snapshot_name: &str) -> Result<DetachedMount, HeldSnapshotTreeErrorV1> {
    mount_detached_snapshot_for(snapshot_name, None)
}

fn mount_detached_snapshot_for(
    snapshot_name: &str,
    original: Option<&mut WorkerOriginalCheckedViewV3<'_>>,
) -> Result<DetachedMount, HeldSnapshotTreeErrorV1> {
    let mut mount = None;
    mount_detached_snapshot_into(snapshot_name, original, &mut mount)?;
    mount.ok_or(HeldSnapshotTreeErrorV1::Unsupported)
}

fn mount_detached_snapshot_into(
    snapshot_name: &str,
    mut original: Option<&mut WorkerOriginalCheckedViewV3<'_>>,
    retained_mount: &mut Option<DetachedMount>,
) -> Result<(), HeldSnapshotTreeErrorV1> {
    if retained_mount.is_some() {
        return Err(HeldSnapshotTreeErrorV1::Unsupported);
    }
    check_original(&mut original)?;
    let mut context = FileSystemContext::open("zfs")?;
    check_original(&mut original)?;
    context.set_string("source", snapshot_name)?;
    check_original(&mut original)?;
    // The lower consuming create/mount prefix can fail before handoff. Once
    // returned, this exact mount enters its owner's slot before postchecks.
    *retained_mount = Some(context.create()?.mount()?);
    check_original(&mut original)?;
    let mount = retained_mount
        .as_ref()
        .ok_or(HeldSnapshotTreeErrorV1::Unsupported)?;
    mount.set_attributes(
        true,
        MountAttributes::secure_read_only().with_no_exec(true),
        None,
    )?;
    check_original(&mut original)?;
    Ok(())
}

fn check_original(
    original: &mut Option<&mut WorkerOriginalCheckedViewV3<'_>>,
) -> Result<(), HeldSnapshotTreeErrorV1> {
    if let Some(original) = original.as_deref_mut() {
        original
            .check_for_tree()
            .map_err(|_| HeldSnapshotTreeErrorV1::Unsupported)?;
    }
    Ok(())
}

/// Measures an exact fixture snapshot from a detached, secured ZFS mount.
///
/// This feature-only entry point issues no receipt or authority. The snapshot
/// name is supplied by the isolated VM test, not by a production caller.
///
/// # Errors
///
/// Rejects mount failures, unsupported physical state, or a mismatched digest.
#[cfg(feature = "held-tree-fixture")]
pub fn run_held_snapshot_tree_fixture(
    snapshot: &str,
    expected: Option<ObjectDigest>,
) -> Result<String, HeldSnapshotTreeErrorV1> {
    let measured = measure_detached_snapshot(snapshot)?;
    fixture_report(measured, expected)
}

/// Measures a VM fixture only if its detached mount proves exact ZFS GUIDs.
///
/// This is test evidence, not a receipt or a production authority path.
///
/// # Errors
///
/// Rejects absent or mismatched mounted UUIDs, unsupported trees, or a
/// mismatched content commitment.
#[cfg(feature = "held-tree-fixture")]
pub fn run_bound_held_snapshot_tree_fixture(
    snapshot: &str,
    expected: ObjectDigest,
    expected_pool_guid: u64,
    expected_snapshot_guid: u64,
) -> Result<String, HeldSnapshotTreeErrorV1> {
    let measured =
        measure_bound_detached_snapshot(snapshot, expected_pool_guid, expected_snapshot_guid)?;
    fixture_report(measured, Some(expected))
}

#[cfg(feature = "held-tree-fixture")]
fn fixture_report(
    measured: MeasuredHeldSnapshotTreeV1,
    expected: Option<ObjectDigest>,
) -> Result<String, HeldSnapshotTreeErrorV1> {
    if expected.is_some_and(|digest| digest != measured.content_digest) {
        return Err(HeldSnapshotTreeErrorV1::Mismatch);
    }
    Ok(serde_json::json!({
        "schema_version": "aos.sandbox.held-tree-fixture/v1",
        "mount_id": measured.mount_id.get(),
        "root_device": measured.root_device,
        "root_inode": measured.root_inode,
        "tree_digest": measured.tree.digest().to_string(),
        "tree_size": measured.tree.encoded_size(),
        "content_digest": measured.content_digest.to_string(),
        "nodes": measured.nodes,
        "file_bytes": measured.file_bytes,
        "root_uid": measured.identity.root_attributes.uid(),
        "root_gid": measured.identity.root_attributes.gid(),
        "root_mode": measured.identity.root_attributes.mode(),
        "maximum_portable_uid": measured.identity.maximum_portable_uid,
        "maximum_portable_gid": measured.identity.maximum_portable_gid,
        "distinct_inode_count": measured.identity.distinct_inode_count,
        "directory_entry_count": measured.identity.directory_entry_count,
        "identity_tree_digest": measured.identity.identity_tree_digest.to_string(),
    })
    .to_string())
}

#[derive(Default)]
struct PhysicalTreeWalker<'loan, 'records> {
    original: Option<&'loan mut WorkerOriginalCheckedViewV3<'records>>,
    nodes: usize,
    file_bytes: usize,
    object_bytes: usize,
    root_attributes: Option<PortableRootAttributesV1>,
    maximum_portable_uid: u32,
    maximum_portable_gid: u32,
    directory_entry_count: u64,
    identity_hasher: Sha256,
}

impl PhysicalTreeWalker<'_, '_> {
    fn check_original(&mut self) -> Result<(), HeldSnapshotTreeErrorV1> {
        check_original(&mut self.original)
    }

    fn measure_tree(
        &mut self,
        root: &BeneathRoot,
    ) -> Result<ObjectDescriptor, HeldSnapshotTreeErrorV1> {
        self.check_original()?;
        self.identity_hasher.update(IDENTITY_TREE_DOMAIN);
        let directory = self.measure_directory(root, Path::new(""), 0)?;
        let tree =
            Tree::new(directory, Vec::new()).map_err(|_| HeldSnapshotTreeErrorV1::Unsupported)?;
        self.object(PortableMediaType::Tree, &encode_tree(&tree))
    }

    fn measure_directory(
        &mut self,
        root: &BeneathRoot,
        relative: &Path,
        depth: usize,
    ) -> Result<ObjectDescriptor, HeldSnapshotTreeErrorV1> {
        self.check_original()?;
        if depth > MAXIMUM_DEPTH {
            return Err(HeldSnapshotTreeErrorV1::Unsupported);
        }
        self.add_node()?;

        let directory = if relative.as_os_str().is_empty() {
            rustix::io::dup(root.as_fd())?
        } else {
            root.resolve(relative, ResolveOptions::directory())?
                .as_fd()
                .try_clone_to_owned()?
        };
        let before = rustix::fs::fstat(directory.as_fd())?;
        let readable = rustix::fs::openat(
            directory.as_fd(),
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let metadata = portable_metadata(readable.as_fd(), &before)?;
        self.record_identity_node(relative, b'd', &before)?;
        let mut names = Vec::new();
        for entry in rustix::fs::Dir::new(readable)? {
            self.check_original()?;
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if matches!(name, b"." | b"..") {
                continue;
            }
            if self.original.is_some() {
                if names.len() >= MAXIMUM_NODES {
                    return Err(HeldSnapshotTreeErrorV1::Unsupported);
                }
                names
                    .try_reserve(1)
                    .map_err(|_| HeldSnapshotTreeErrorV1::Unsupported)?;
            }
            names.push(
                PathName::new(name.to_vec()).map_err(|_| HeldSnapshotTreeErrorV1::Unsupported)?,
            );
            if names.len() > MAXIMUM_NODES {
                return Err(HeldSnapshotTreeErrorV1::Unsupported);
            }
        }
        names.sort();
        if names.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(HeldSnapshotTreeErrorV1::Unsupported);
        }

        let mut entries = Vec::with_capacity(names.len());
        for name in names {
            self.check_original()?;
            let mut child = relative.to_path_buf();
            child.push(OsString::from_vec(name.as_bytes().to_vec()));
            let pinned = root.resolve(&child, ResolveOptions::any())?;
            let node = match pinned.identity().file_type {
                FileType::Directory => {
                    Node::Directory(self.measure_directory(root, &child, depth + 1)?)
                }
                FileType::Regular => self.measure_file(root, &child, pinned.identity())?,
                FileType::Symlink | FileType::Other => {
                    return Err(HeldSnapshotTreeErrorV1::Unsupported);
                }
            };
            self.directory_entry_count = self
                .directory_entry_count
                .checked_add(1)
                .ok_or(HeldSnapshotTreeErrorV1::Unsupported)?;
            entries.push(DirectoryEntry { name, node });
        }
        if !same_inode_state(&before, &rustix::fs::fstat(directory.as_fd())?) {
            return Err(HeldSnapshotTreeErrorV1::Unsupported);
        }
        let directory =
            Directory::new(metadata, entries).map_err(|_| HeldSnapshotTreeErrorV1::Unsupported)?;
        self.check_original()?;
        self.object(PortableMediaType::Directory, &encode_directory(&directory))
    }

    fn measure_file(
        &mut self,
        root: &BeneathRoot,
        relative: &Path,
        pinned: aos_sandbox_linux::path::FileIdentity,
    ) -> Result<Node, HeldSnapshotTreeErrorV1> {
        self.check_original()?;
        self.add_node()?;
        let file = root.open_regular(relative)?;
        if file.identity() != pinned {
            return Err(HeldSnapshotTreeErrorV1::Unsupported);
        }
        let before = rustix::fs::fstat(file.as_fd())?;
        let size =
            usize::try_from(before.st_size).map_err(|_| HeldSnapshotTreeErrorV1::Unsupported)?;
        if before.st_nlink != 1
            || size > MAXIMUM_FILE_BYTES
            || self
                .file_bytes
                .checked_add(size)
                .is_none_or(|total| total > MAXIMUM_TOTAL_BYTES)
        {
            return Err(HeldSnapshotTreeErrorV1::Unsupported);
        }
        let metadata = portable_metadata(file.as_fd(), &before)?;
        self.record_identity_node(relative, b'f', &before)?;
        if size != 0
            && (rustix::fs::seek(file.as_fd(), SeekFrom::Data(0))? != 0
                || rustix::fs::seek(file.as_fd(), SeekFrom::Hole(0))? != size as u64)
        {
            return Err(HeldSnapshotTreeErrorV1::Unsupported);
        }
        rustix::fs::seek(file.as_fd(), SeekFrom::Start(0))?;

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size)
            .map_err(|_| HeldSnapshotTreeErrorV1::Unsupported)?;
        let reader = std::fs::File::from(rustix::io::dup(file.as_fd())?);
        if self.original.is_some() {
            // One bounded read is followed by the same paired-clock/peer check.
            // An in-flight kernel read is not universally preemptible.
            bytes
                .try_reserve_exact(1)
                .map_err(|_| HeldSnapshotTreeErrorV1::Unsupported)?;
            let mut reader = reader.take((size as u64) + 1);
            let mut scratch = [0_u8; 64 * 1024];
            loop {
                self.check_original()?;
                let read = reader.read(&mut scratch);
                let postcheck = self.check_original();
                match read {
                    Ok(0) => {
                        postcheck?;
                        break;
                    }
                    Ok(count) => {
                        postcheck?;
                        bytes.extend_from_slice(&scratch[..count]);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                        postcheck?;
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        } else {
            reader.take((size as u64) + 1).read_to_end(&mut bytes)?;
        }
        self.check_original()?;
        if bytes.len() != size || !same_inode_state(&before, &rustix::fs::fstat(file.as_fd())?) {
            return Err(HeldSnapshotTreeErrorV1::Unsupported);
        }
        self.file_bytes += size;
        let content = self.object(PortableMediaType::Content, &bytes)?;
        Ok(Node::File(FileNode {
            metadata,
            content: ContentLayout::whole(content),
            hardlink_group: None,
        }))
    }

    fn add_node(&mut self) -> Result<(), HeldSnapshotTreeErrorV1> {
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or(HeldSnapshotTreeErrorV1::Unsupported)?;
        if self.nodes > MAXIMUM_NODES {
            return Err(HeldSnapshotTreeErrorV1::Unsupported);
        }
        Ok(())
    }

    fn record_identity_node(
        &mut self,
        relative: &Path,
        kind: u8,
        stat: &Stat,
    ) -> Result<(), HeldSnapshotTreeErrorV1> {
        let attributes =
            PortableRootAttributesV1::new(stat.st_uid, stat.st_gid, stat.st_mode & 0o7777)
                .map_err(|_| HeldSnapshotTreeErrorV1::Unsupported)?;
        if relative.as_os_str().is_empty() {
            self.root_attributes = Some(attributes);
        }

        let path = relative.as_os_str().as_bytes();
        let path_length =
            u32::try_from(path.len()).map_err(|_| HeldSnapshotTreeErrorV1::Unsupported)?;
        self.identity_hasher.update([kind]);
        self.identity_hasher.update(path_length.to_be_bytes());
        self.identity_hasher.update(path);
        self.identity_hasher.update(attributes.uid().to_be_bytes());
        self.identity_hasher.update(attributes.gid().to_be_bytes());
        self.identity_hasher.update(attributes.mode().to_be_bytes());
        self.maximum_portable_uid = self.maximum_portable_uid.max(attributes.uid());
        self.maximum_portable_gid = self.maximum_portable_gid.max(attributes.gid());
        Ok(())
    }

    fn identity_observation(
        &self,
    ) -> Result<HeldSnapshotIdentityObservationV1, HeldSnapshotTreeErrorV1> {
        let root_attributes = self
            .root_attributes
            .ok_or(HeldSnapshotTreeErrorV1::Unsupported)?;
        let distinct_inode_count =
            u64::try_from(self.nodes).map_err(|_| HeldSnapshotTreeErrorV1::Unsupported)?;
        if distinct_inode_count == 0 || self.directory_entry_count != distinct_inode_count - 1 {
            return Err(HeldSnapshotTreeErrorV1::Unsupported);
        }

        Ok(HeldSnapshotIdentityObservationV1 {
            root_attributes,
            maximum_portable_uid: self.maximum_portable_uid,
            maximum_portable_gid: self.maximum_portable_gid,
            distinct_inode_count,
            directory_entry_count: self.directory_entry_count,
            identity_tree_digest: ObjectDigest::from_bytes(
                self.identity_hasher.clone().finalize().into(),
            ),
        })
    }

    fn object(
        &mut self,
        kind: PortableMediaType,
        bytes: &[u8],
    ) -> Result<ObjectDescriptor, HeldSnapshotTreeErrorV1> {
        self.check_original()?;
        self.object_bytes = self
            .object_bytes
            .checked_add(bytes.len())
            .ok_or(HeldSnapshotTreeErrorV1::Unsupported)?;
        if self.object_bytes > MAXIMUM_TOTAL_BYTES {
            return Err(HeldSnapshotTreeErrorV1::Unsupported);
        }
        let media =
            MediaType::new(kind.as_str()).map_err(|_| HeldSnapshotTreeErrorV1::Unsupported)?;
        Ok(descriptor_for_bytes(media, bytes))
    }
}

fn portable_metadata(
    fd: std::os::fd::BorrowedFd<'_>,
    stat: &Stat,
) -> Result<FilesystemMetadata, HeldSnapshotTreeErrorV1> {
    // A zero-length query reports the presence of any xattr without copying
    // attacker-controlled names or values. ACLs are xattrs on this platform.
    if rustix::fs::flistxattr(fd, &mut [] as &mut [u8])? != 0 {
        return Err(HeldSnapshotTreeErrorV1::Unsupported);
    }
    let mode =
        u16::try_from(stat.st_mode & 0o7777).map_err(|_| HeldSnapshotTreeErrorV1::Unsupported)?;
    let nanos =
        u32::try_from(stat.st_mtime_nsec).map_err(|_| HeldSnapshotTreeErrorV1::Unsupported)?;
    FilesystemMetadata::new(
        mode,
        stat.st_uid,
        stat.st_gid,
        stat.st_mtime,
        nanos,
        Vec::new(),
        None,
    )
    .map_err(|_| HeldSnapshotTreeErrorV1::Unsupported)
}

fn same_inode_state(before: &Stat, after: &Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_uid == after.st_uid
        && before.st_gid == after.st_gid
        && before.st_size == after.st_size
        && before.st_nlink == after.st_nlink
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

#[cfg(test)]
mod tests {
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use super::*;

    fn root(directory: &tempfile::TempDir) -> BeneathRoot {
        let descriptor: OwnedFd = std::fs::File::open(directory.path()).unwrap().into();
        BeneathRoot::from_owned(descriptor).unwrap()
    }

    #[test]
    fn measured_file_bytes_change_the_portable_tree_commitment() {
        let directory = tempfile::TempDir::new().unwrap();
        std::fs::write(directory.path().join("payload"), b"alpha").unwrap();
        let first = PhysicalTreeWalker::default()
            .measure_tree(&root(&directory))
            .unwrap();

        std::fs::write(directory.path().join("payload"), b"bravo").unwrap();
        let second = PhysicalTreeWalker::default()
            .measure_tree(&root(&directory))
            .unwrap();

        assert_ne!(first, second);
        assert_ne!(
            held_snapshot_content_digest_v1(&first),
            held_snapshot_content_digest_v1(&second),
        );
    }

    #[test]
    fn identity_summary_covers_every_accepted_inode_and_path() {
        let directory = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(directory.path().join("nested")).unwrap();
        std::fs::write(directory.path().join("nested/payload"), b"alpha").unwrap();

        let mut walker = PhysicalTreeWalker::default();
        walker.measure_tree(&root(&directory)).unwrap();
        let original = walker.identity_observation().unwrap();
        let root_stat = std::fs::metadata(directory.path()).unwrap();
        assert_eq!(original.root_attributes.uid(), root_stat.uid());
        assert_eq!(original.root_attributes.gid(), root_stat.gid());
        assert_eq!(
            original.root_attributes.mode(),
            (root_stat.mode() & 0o7777) as u16
        );
        assert_eq!(original.maximum_portable_uid, root_stat.uid());
        assert_eq!(original.maximum_portable_gid, root_stat.gid());
        assert_eq!(original.distinct_inode_count, 3);
        assert_eq!(original.directory_entry_count, 2);

        std::fs::write(directory.path().join("nested/payload"), b"bravo").unwrap();
        let mut content_changed = PhysicalTreeWalker::default();
        content_changed.measure_tree(&root(&directory)).unwrap();
        assert_eq!(content_changed.identity_observation().unwrap(), original);

        std::fs::rename(
            directory.path().join("nested/payload"),
            directory.path().join("nested/renamed"),
        )
        .unwrap();
        let mut path_changed = PhysicalTreeWalker::default();
        path_changed.measure_tree(&root(&directory)).unwrap();
        assert_ne!(
            path_changed
                .identity_observation()
                .unwrap()
                .identity_tree_digest,
            original.identity_tree_digest
        );

        let file = directory.path().join("nested/renamed");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut mode_changed = PhysicalTreeWalker::default();
        mode_changed.measure_tree(&root(&directory)).unwrap();
        assert_ne!(
            mode_changed
                .identity_observation()
                .unwrap()
                .identity_tree_digest,
            path_changed
                .identity_observation()
                .unwrap()
                .identity_tree_digest,
        );
    }

    #[test]
    fn identity_tree_digest_matches_the_documented_root_and_file_vector() {
        let directory = tempfile::TempDir::new().unwrap();
        let file_path = directory.path().join("payload");
        std::fs::write(&file_path, b"bytes").unwrap();

        let mut root_stat =
            rustix::fs::fstat(&std::fs::File::open(directory.path()).unwrap()).unwrap();
        root_stat.st_uid = 0;
        root_stat.st_gid = 0;
        root_stat.st_mode = (root_stat.st_mode & !0o7777) | 0o755;

        let mut file_stat = rustix::fs::fstat(&std::fs::File::open(&file_path).unwrap()).unwrap();
        file_stat.st_uid = 42;
        file_stat.st_gid = 43;
        file_stat.st_mode = (file_stat.st_mode & !0o7777) | 0o644;

        let mut walker = PhysicalTreeWalker::default();
        walker.identity_hasher.update(IDENTITY_TREE_DOMAIN);
        walker
            .record_identity_node(Path::new(""), b'd', &root_stat)
            .unwrap();
        walker
            .record_identity_node(Path::new("payload"), b'f', &file_stat)
            .unwrap();
        walker.nodes = 2;
        walker.directory_entry_count = 1;

        let observation = walker.identity_observation().unwrap();
        assert_eq!(observation.root_attributes.uid(), 0);
        assert_eq!(observation.root_attributes.gid(), 0);
        assert_eq!(observation.root_attributes.mode(), 0o755);
        assert_eq!(observation.maximum_portable_uid, 42);
        assert_eq!(observation.maximum_portable_gid, 43);
        assert_eq!(observation.distinct_inode_count, 2);
        assert_eq!(observation.directory_entry_count, 1);
        assert_eq!(
            observation.identity_tree_digest.to_string(),
            "sha256:d96f62fc5f9c09ace8b0e2ce8ec2d746df8aeee6d0d0661c7019a9e2924f76b7",
        );
    }

    #[test]
    fn unsupported_symlink_and_hardlink_close_measurement() {
        let directory = tempfile::TempDir::new().unwrap();
        std::fs::write(directory.path().join("payload"), b"bytes").unwrap();
        std::fs::hard_link(
            directory.path().join("payload"),
            directory.path().join("linked"),
        )
        .unwrap();
        assert!(
            PhysicalTreeWalker::default()
                .measure_tree(&root(&directory))
                .is_err()
        );

        std::fs::remove_file(directory.path().join("linked")).unwrap();
        std::os::unix::fs::symlink("payload", directory.path().join("link")).unwrap();
        assert!(
            PhysicalTreeWalker::default()
                .measure_tree(&root(&directory))
                .is_err()
        );
    }

    #[test]
    fn mounted_uuid_requires_exact_pool_and_snapshot_guids() {
        let mut uuid = [0; 16];
        uuid[..8].copy_from_slice(&7_u64.to_be_bytes());
        uuid[8..].copy_from_slice(&9_u64.to_be_bytes());

        assert!(verify_mounted_snapshot_uuid(uuid, 7, 9).is_ok());
        assert!(matches!(
            verify_mounted_snapshot_uuid(uuid, 8, 9),
            Err(HeldSnapshotTreeErrorV1::MountGuidMismatch)
        ));
        assert!(matches!(
            verify_mounted_snapshot_uuid(uuid, 7, 10),
            Err(HeldSnapshotTreeErrorV1::MountGuidMismatch)
        ));
    }
}
