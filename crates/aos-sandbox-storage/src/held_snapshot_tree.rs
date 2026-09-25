//! Bounded physical measurement of the portable subset of a held snapshot.
//!
//! The input is an already-pinned snapshot root descriptor, not a pathname.
//! Every descendant is resolved beneath that root without following symlinks
//! or crossing mounts. Unsupported portable state closes measurement; this
//! module neither acquires the root nor signs an AOSPCZ01 receipt.

use std::ffi::OsString;
use std::io::Read as _;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::ffi::OsStringExt as _;
use std::path::Path;

use aos_sandbox_core::format::{encode_directory, encode_tree};
use aos_sandbox_core::model::tree::{
    ContentLayout, Directory, DirectoryEntry, FileNode, FilesystemMetadata, Node, Tree,
};
use aos_sandbox_core::{
    MediaType, ObjectDescriptor, ObjectDigest, PathName, PortableMediaType, descriptor_for_bytes,
};
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::mount::{FileSystemContext, MountAttributes};
use aos_sandbox_linux::path::{BeneathRoot, FileType, ResolveOptions};
use aos_sandbox_source_provider_protocol::held_snapshot_content_digest_v1;
use rustix::fs::{Mode, OFlags, SeekFrom, Stat, StatVfsMountFlags};

const MAXIMUM_DEPTH: usize = 64;
const MAXIMUM_NODES: usize = 4096;
const MAXIMUM_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_TOTAL_BYTES: usize = 64 * 1024 * 1024;

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
    let mut walker = PhysicalTreeWalker::default();
    let tree = walker.measure_tree(&beneath)?;
    let final_stat = rustix::fs::fstat(beneath.as_fd())?;
    if !same_inode_state(&root_stat, &final_stat) || MountId::from_fd(beneath.as_fd())? != mount_id
    {
        return Err(HeldSnapshotTreeErrorV1::Unsupported);
    }
    let content_digest =
        held_snapshot_content_digest_v1(&tree).map_err(|_| HeldSnapshotTreeErrorV1::Unsupported)?;
    Ok(MeasuredHeldSnapshotTreeV1 {
        mount_id,
        root_device: root_stat.st_dev,
        root_inode: root_stat.st_ino,
        tree,
        content_digest,
        nodes: walker.nodes,
        file_bytes: walker.file_bytes,
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
    let mut context = FileSystemContext::open("zfs")?;
    context.set_string("source", snapshot_name)?;
    let mount = context.create()?.mount()?;
    mount.set_attributes(
        true,
        MountAttributes::secure_read_only().with_no_exec(true),
        None,
    )?;
    measure_secure_root(rustix::io::dup(mount.as_fd())?)
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
    })
    .to_string())
}

#[derive(Default)]
struct PhysicalTreeWalker {
    nodes: usize,
    file_bytes: usize,
    object_bytes: usize,
}

impl PhysicalTreeWalker {
    fn measure_tree(
        &mut self,
        root: &BeneathRoot,
    ) -> Result<ObjectDescriptor, HeldSnapshotTreeErrorV1> {
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
        let mut names = Vec::new();
        for entry in rustix::fs::Dir::new(readable)? {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if matches!(name, b"." | b"..") {
                continue;
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
            entries.push(DirectoryEntry { name, node });
        }
        if !same_inode_state(&before, &rustix::fs::fstat(directory.as_fd())?) {
            return Err(HeldSnapshotTreeErrorV1::Unsupported);
        }
        let directory =
            Directory::new(metadata, entries).map_err(|_| HeldSnapshotTreeErrorV1::Unsupported)?;
        self.object(PortableMediaType::Directory, &encode_directory(&directory))
    }

    fn measure_file(
        &mut self,
        root: &BeneathRoot,
        relative: &Path,
        pinned: aos_sandbox_linux::path::FileIdentity,
    ) -> Result<Node, HeldSnapshotTreeErrorV1> {
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
        reader.take((size as u64) + 1).read_to_end(&mut bytes)?;
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

    fn object(
        &mut self,
        kind: PortableMediaType,
        bytes: &[u8],
    ) -> Result<ObjectDescriptor, HeldSnapshotTreeErrorV1> {
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
}
