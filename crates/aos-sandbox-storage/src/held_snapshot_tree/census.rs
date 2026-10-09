//! Retained canonical objects and Linux metadata for the selected census walk.
//!
//! The containing physical walker owns traversal and original native results.
//! This child owns the bounded object arena and the one Linux ACL/capability
//! interpretation. Its outputs are DATA; none opens a Snapshot or admits G0.
//!
//! ```text
//! Linux ACL: LEu32 version2 | repeated(LEu16 tag, LEu16 perms, LEu32 id)
//! file capabilities: LEu32 revision/flags | capability words | optional rootID
//! arena: exact Core ObjectDescriptor -> original canonical encoded bytes
//! ```

use std::ffi::CString;
use std::io::Cursor;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};

use aos_filesystem_view_core::ObjectSource;
use aos_sandbox_linux::path::{BeneathRoot, FileType, ResolveOptions, ResolvedFile, ResolvedPath};
use aos_sandbox_linux::protected_file::{ExactReadFailure, read_exact_positioned_census_retaining_cause};
use aos_sandbox_core::model::{
    Acl, AclEntry, ContentLayout, Directory, DirectoryEntry, FileNode,
    FilesystemMetadata, Node, SymlinkNode, Tree, Xattr,
};
use aos_sandbox_core::{
    FeatureRef, MediaType, ObjectDescriptor, ObjectDigest, PathName, PortableMediaType,
    RelativePath, descriptor_for_bytes, hardlink_group_digest,
};
use rustix::fs::{AtFlags, Mode, OFlags, Stat};

const MAXIMUM_CANONICAL_BYTES: usize = 80 * 1024 * 1024;
const MAXIMUM_ARENA_BYTES: usize = 224 * 1024 * 1024;
// Each physical node contributes at most one distinct Content or Directory
// object; the complete graph adds exactly one Tree object.
const MAXIMUM_OBJECTS: usize = super::MAXIMUM_NODES + 1;
const MAXIMUM_ACL_ENTRIES: usize = 65536;
const MAXIMUM_XATTRS: usize = 16384;
const MAXIMUM_XATTR_BYTES: usize = 8 * 1024 * 1024;
const MAXIMUM_XATTR_LIST_BYTES: usize = 64 * 1024;
const MAXIMUM_XATTR_VALUE_BYTES: usize = 64 * 1024;
const ACL_UNDEFINED_ID: u32 = u32::MAX;

enum CensusNodeKind {
    Directory { entries: Vec<(PathName, usize)>, descriptor: Option<ObjectDescriptor> },
    File { content: ObjectDescriptor, group: Option<ObjectDigest> },
    Symlink,
}

/// Holds originals while the containing walker visits one closed node kind.
///
/// Successful descriptors retire only after their original inode bookends.
/// Errors and unwinds leave the current directory/file/link candidate resident;
/// no lower unreturned open/adoption prefix is claimed by these slots.
struct CensusNodeCapture {
    path: PathBuf,
    path_capacity: usize,
    portable_path: RelativePath,
    portable_path_capacity: usize,
    resolved: Option<Result<ResolvedPath, aos_sandbox_linux::Error>>,
    readable: Option<Result<OwnedFd, rustix::io::Errno>>,
    file: Option<Result<ResolvedFile, aos_sandbox_linux::Error>>,
    symlink: Option<Result<OwnedFd, rustix::io::Errno>>,
    inode: [Option<Result<Stat, rustix::io::Errno>>; 3],
    terminal_inode: Option<Result<Stat, rustix::io::Errno>>,
    mount: Option<Result<aos_sandbox_linux::inventory::MountId, aos_sandbox_linux::Error>>,
    metadata: CensusMetadataCapture,
    metadata_summary: Option<CensusMetadataSummary>,
    model: Option<FilesystemMetadata>,
    directory_names: Option<CensusDirectoryNames>,
    content: CensusContentCapture,
    target: Vec<u8>,
    target_read: Option<Result<usize, rustix::io::Errno>>,
    kind: Option<CensusNodeKind>,
    outcome: Option<Result<(), CensusDataError>>,
    postcheck: Option<Result<(), CensusDataError>>,
}

struct CensusDirectoryFrame {
    node: usize,
    names: std::vec::IntoIter<PathName>,
    parent: Option<(usize, PathName)>,
}

pub(super) enum CensusVisit {
    Child { parent: usize, name: PathName },
    FinishDirectory(usize),
}

/// Retains the selected route's observations and complete canonical closure.
///
/// Traversal remains in the sole containing `PhysicalTreeWalker`. Delayed
/// directory encoding is necessary: a hardlink digest binds ALL member paths,
/// so no placeholder directory or provisional group descriptor is emitted.
#[derive(Default)]
pub(crate) struct CensusWalkState {
    records: Vec<CensusNodeCapture>,
    directories: Vec<CensusDirectoryFrame>,
    pub(crate) arena: CensusObjectArena,
    pub(crate) counters: crate::snapshot_metadata::census::SnapshotCensusCountersV2,
    pub(crate) maximum_uid: u32,
    pub(crate) maximum_gid: u32,
    pub(crate) tree: Option<ObjectDescriptor>,
    root_mount: Option<Result<aos_sandbox_linux::inventory::MountId, aos_sandbox_linux::Error>>,
    first_failed_node: Option<usize>,
    preparation_failure: Option<CensusDataError>,
    outcome: Option<Result<(), CensusDataError>>,
    graph: Option<Result<
        aos_filesystem_view_core::StorageCensusValidation<Cursor<Vec<u8>>>,
        aos_filesystem_view_core::CompileError<CensusDataError>,
    >>,
    walk_name_capacity: usize,
    graph_writer_capacity: usize,
    complete: bool,
}

impl CensusWalkState {
    pub(crate) fn begin(&mut self, root: &BeneathRoot) -> Result<(), CensusDataError> {
        if self.root_mount.is_some() || !self.records.is_empty() {
            return Err(CensusDataError::Closed);
        }
        // The explicit active-depth stack is admitted before the first
        // native crossing. Failed frames remain in this externally held owner.
        self.directories.try_reserve_exact(super::MAXIMUM_DEPTH + 1)?;
        self.root_mount = Some(aos_sandbox_linux::inventory::MountId::from_fd(root.as_fd()));
        original_linux(&self.root_mount)?;
        self.prepare_node(Path::new(""))?;
        Ok(())
    }

    pub(super) fn prepare_node(&mut self, relative: &Path) -> Result<usize, CensusDataError> {
        if self.complete
            || self.first_failed_node.is_some()
            || self.records.len() == super::MAXIMUM_NODES
        {
            return Err(CensusDataError::Closed);
        }

        let mut path = PathBuf::new();
        path.try_reserve_exact(relative.as_os_str().len())?;
        path.push(relative);
        let path_capacity = path.capacity();

        let mut components = Vec::new();
        let mut portable_path_capacity = 0_usize;
        for component in relative.components() {
            let std::path::Component::Normal(component) = component else {
                return Err(CensusDataError::Metadata);
            };
            components.try_reserve_exact(1)?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(component.len())?;
            bytes.extend_from_slice(component.as_bytes());
            portable_path_capacity = portable_path_capacity
                .checked_add(bytes.capacity())
                .ok_or(CensusDataError::Capacity)?;
            components.push(PathName::new(bytes)?);
        }
        portable_path_capacity = portable_path_capacity
            .checked_add(
                components.capacity().checked_mul(std::mem::size_of::<PathName>())
                    .ok_or(CensusDataError::Capacity)?,
            )
            .ok_or(CensusDataError::Capacity)?;
        let portable_path = RelativePath::new(components).map_err(|_| CensusDataError::Metadata)?;

        self.records.try_reserve_exact(1)?;
        let index = self.records.len();
        self.records.push(CensusNodeCapture {
            path,
            path_capacity,
            portable_path,
            portable_path_capacity,
            resolved: None,
            readable: None,
            file: None,
            symlink: None,
            inode: [None, None, None],
            terminal_inode: None,
            mount: None,
            metadata: CensusMetadataCapture::default(),
            metadata_summary: None,
            model: None,
            directory_names: None,
            content: CensusContentCapture::default(),
            target: Vec::new(),
            target_read: None,
            kind: None,
            outcome: None,
            postcheck: None,
        });
        self.check_capacity()?;
        Ok(index)
    }

    pub(super) fn prepare_child(&mut self, parent: usize, name: &PathName) -> Result<usize, CensusDataError> {
        // Depth applies to every node, not only directories. The active root
        // frame counts as depth zero; a file/link below depth64 is still a
        // depth65 node and must refuse before its path or descriptor is made.
        if self.directories.len() > super::MAXIMUM_DEPTH {
            return Err(CensusDataError::Capacity);
        }
        let path = &self.records.get(parent).ok_or(CensusDataError::Closed)?.path;
        let length = path.as_os_str().len().checked_add(name.as_bytes().len())
            .and_then(|value| value.checked_add(1)).filter(|value| *value <= 4096)
            .ok_or(CensusDataError::Capacity)?;
        let mut child = PathBuf::new();
        child.try_reserve_exact(length)?;
        child.push(path);
        child.push(std::ffi::OsStr::from_bytes(name.as_bytes()));
        self.prepare_node(&child)
    }

    pub(super) fn start_directory(
        &mut self, root: &BeneathRoot, index: usize, parent: Option<(usize, PathName)>,
    ) -> Result<(), CensusDataError> {
        if self.directories.len() > super::MAXIMUM_DEPTH
            || self.directories.len() == self.directories.capacity()
        { return Err(CensusDataError::Capacity); }
        self.directories.push(CensusDirectoryFrame {
            node: index, names: Vec::new().into_iter(), parent,
        });
        let names = self.begin_directory(root, index)?;
        let frame = self.directories.last_mut().ok_or(CensusDataError::Closed)?;
        frame.names = names.into_iter();
        Ok(())
    }

    pub(super) fn next_visit(&mut self) -> Option<CensusVisit> {
        let frame = self.directories.last_mut()?;
        Some(match frame.names.next() {
            Some(name) => CensusVisit::Child { parent: frame.node, name },
            None => CensusVisit::FinishDirectory(frame.node),
        })
    }

    pub(super) fn retire_directory(&mut self, index: usize) -> Result<(), CensusDataError> {
        if self.directories.last().is_none_or(|frame| frame.node != index) {
            return Err(CensusDataError::Closed);
        }
        let frame = self.directories.pop().ok_or(CensusDataError::Closed)?;
        if let Some((parent, name)) = frame.parent {
            self.add_child(parent, name, index)?;
        }
        Ok(())
    }

    pub(super) fn post_active_directories(&mut self) {
        for slot in (0..self.directories.len()).rev() {
            let index = self.directories[slot].node;
            let _post = self.post_node(index);
        }
    }

    /// Parks the exact same-parent native cut before deciding how to open it.
    pub(super) fn inspect_child(
        &mut self, root: &BeneathRoot, parent: usize, child: usize, name: &PathName,
    ) -> Result<FileType, CensusDataError> {
        if parent >= child || child >= self.records.len() {
            return Err(CensusDataError::Closed);
        }
        let (parents, children) = self.records.split_at_mut(child);
        let parent = &parents[parent];
        let node = &mut children[0];
        let directory = original_native(&parent.readable)?;
        node.inode[0] = Some(rustix::fs::statat(
            directory.as_fd(), std::ffi::OsStr::from_bytes(name.as_bytes()),
            AtFlags::SYMLINK_NOFOLLOW,
        ));
        let before = *original_native(&node.inode[0])?;
        let kind = rustix::fs::FileType::from_raw_mode(before.st_mode);
        if kind == rustix::fs::FileType::Symlink {
            // O_PATH|NOFOLLOW pins the final link itself. No string-target
            // traversal or second beneath-root resolver is introduced.
            node.symlink = Some(rustix::fs::openat(
                directory.as_fd(), std::ffi::OsStr::from_bytes(name.as_bytes()),
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty(),
            ));
            let original = original_native(&node.symlink)?;
            node.inode[1] = Some(rustix::fs::fstat(original.as_fd()));
            node.mount = Some(aos_sandbox_linux::inventory::MountId::from_fd(original.as_fd()));
            if !super::same_inode_state(&before, original_native(&node.inode[1])?)
                || original_linux(&node.mount)? != original_linux(&self.root_mount)?
            {
                return Err(CensusDataError::Changed);
            }
            return Ok(FileType::Symlink);
        }
        node.resolved = Some(root.resolve(&node.path, ResolveOptions::any()));
        let pinned = original_linux(&node.resolved)?;
        node.inode[1] = Some(rustix::fs::fstat(pinned.as_fd()));
        if !super::same_inode_state(&before, original_native(&node.inode[1])?) {
            return Err(CensusDataError::Changed);
        }
        Ok(pinned.identity().file_type)
    }

    pub(super) fn begin_directory(&mut self, root: &BeneathRoot, index: usize) -> Result<Vec<PathName>, CensusDataError> {
        let node = self.records.get_mut(index).ok_or(CensusDataError::Closed)?;

        // Prepare the complete borrowed getdents scratch before this open.
        node.directory_names = Some(CensusDirectoryNames::prepare()?);
        let original = if index == 0 {
            root.as_fd()
        } else {
            original_linux(&node.resolved)?.as_fd()
        };
        node.readable = Some(rustix::fs::openat(
            original,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ));

        let readable = original_native(&node.readable)?;
        if index == 0 {
            node.inode[0] = Some(rustix::fs::fstat(readable.as_fd()));
        }
        let before = *original_native(&node.inode[0])?;
        node.inode[1] = Some(rustix::fs::fstat(readable.as_fd()));
        node.mount = Some(aos_sandbox_linux::inventory::MountId::from_fd(readable.as_fd()));
        if !super::same_inode_state(&before, original_native(&node.inode[1])?)
            || original_linux(&node.mount)? != original_linux(&self.root_mount)?
        {
            return Err(CensusDataError::Changed);
        }
        node.metadata
            .capture(MetadataSubject::Original(readable.as_fd()), &before)
            .map_err(|_| CensusDataError::NativeObservation)?;
        node.metadata_summary = Some(node.metadata.summary().map_err(|_| CensusDataError::Closed)?);
        node.model = Some(node.metadata.transfer_metadata().map_err(|_| CensusDataError::Closed)?);

        let names = node.directory_names.as_mut().ok_or(CensusDataError::Closed)?;
        names.capture(readable.as_fd(), &before).map_err(|_| CensusDataError::NativeObservation)?;

        let mut walk_names = Vec::new();
        walk_names.try_reserve_exact(names.names().map_err(|_| CensusDataError::Closed)?.len())?;
        let mut name_capacity = walk_names.capacity().checked_mul(std::mem::size_of::<PathName>())
            .ok_or(CensusDataError::Capacity)?;
        for name in names.names().map_err(|_| CensusDataError::Closed)? {
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(name.as_bytes().len())?;
            bytes.extend_from_slice(name.as_bytes());
            name_capacity = name_capacity.checked_add(bytes.capacity()).ok_or(CensusDataError::Capacity)?;
            walk_names.push(PathName::new(bytes)?);
        }
        // The opened readable original now carries the complete directory
        // identity; retiring this successful O_PATH alias saves one FD/depth.
        node.resolved = None;
        node.kind = Some(CensusNodeKind::Directory {
            entries: Vec::new(),
            descriptor: None
        });
        self.walk_name_capacity = self.walk_name_capacity
            .checked_add(name_capacity)
            .ok_or(CensusDataError::Capacity)?;
        self.check_capacity()?;
        Ok(walk_names)
    }

    pub(super) fn add_child(&mut self, parent: usize, name: PathName, child: usize) -> Result<(), CensusDataError> {
        let node = self.records.get_mut(parent).ok_or(CensusDataError::Closed)?;
        let Some(CensusNodeKind::Directory { entries, .. }) = &mut node.kind else {
            return Err(CensusDataError::Closed);
        };
        entries.try_reserve_exact(1)?;
        entries.push((name, child));
        self.check_capacity()
    }

    pub(super) fn finish_directory(&mut self, index: usize) -> Result<(), CensusDataError> {
        let node = self.records.get_mut(index).ok_or(CensusDataError::Closed)?;
        let readable = original_native(&node.readable)?;
        node.inode[2] = Some(rustix::fs::fstat(readable.as_fd()));
        if !super::same_inode_state(original_native(&node.inode[0])?, original_native(&node.inode[2])?) {
            return Err(CensusDataError::Changed);
        }
        // Only complete subtree/inode bookends permit successful retirement.
        // The exact returned observations and accepted names remain resident.
        node.readable = None;
        if let Some(names) = &mut node.directory_names { names.scratch = Vec::new(); }
        self.check_capacity()
    }

    pub(super) fn capture_file(&mut self, root: &BeneathRoot, index: usize) -> Result<(), CensusDataError> {
        let node = self.records.get_mut(index).ok_or(CensusDataError::Closed)?;
        let before = *original_native(&node.inode[0])?;
        node.file = Some(root.open_regular(&node.path));
        let original = original_linux(&node.file)?;
        if original.identity() != original_linux(&node.resolved)?.identity() {
            return Err(CensusDataError::Changed);
        }
        node.metadata.capture(MetadataSubject::Original(original.as_fd()), &before)
            .map_err(|_| CensusDataError::NativeObservation)?;
        node.metadata_summary = Some(node.metadata.summary().map_err(|_| CensusDataError::Closed)?);
        node.model = Some(node.metadata.transfer_metadata().map_err(|_| CensusDataError::Closed)?);
        node.content.capture(original, &before).map_err(|_| CensusDataError::NativeObservation)?;
        let bytes = node.content.transfer_bytes().map_err(|_| CensusDataError::Closed)?;
        let content = self.arena.capture_object(PortableMediaType::Content, bytes)?;
        node.kind = Some(CensusNodeKind::File { content, group: None });
        // The containing walk parks this action Result before the final
        // original-inode observation. Encoding/allocation cannot retire the
        // file early or suppress that independent observation on failure.
        self.check_capacity()
    }

    pub(super) fn capture_symlink(&mut self, parent: usize, index: usize, name: &PathName) -> Result<(), CensusDataError> {
        if parent >= index {
            return Err(CensusDataError::Closed);
        }

        let (parents, children) = self.records.split_at_mut(index);
        let parent = &parents[parent];
        let node = &mut children[0];
        let before = *original_native(&node.inode[0])?;
        if before.st_nlink != 1 {
            return Err(CensusDataError::Metadata);
        }

        node.metadata
            .capture(
                MetadataSubject::Child {
                    parent: original_native(&parent.readable)?.as_fd(),
                    name
                },
                &before
            )
            .map_err(|_| CensusDataError::NativeObservation)?;
        node.metadata_summary = Some(node.metadata.summary().map_err(|_| CensusDataError::Closed)?);
        node.model = Some(node.metadata.transfer_metadata().map_err(|_| CensusDataError::Closed)?);

        node.target.try_reserve_exact(4097)?;
        node.target.resize(4097, 0);
        let original = original_native(&node.symlink)?;
        node.target_read = Some(rustix::fs::readlinkat_raw(
            original.as_fd(), "", &mut node.target[..]
        ));

        // Even failed link reads receive their independent same-inode post.
        node.inode[2] = Some(rustix::fs::fstat(original.as_fd()));
        let length = *original_native(&node.target_read)?;
        if length > 4096 || !super::same_inode_state(&before, original_native(&node.inode[2])?) {
            return Err(CensusDataError::Changed);
        }
        node.target.truncate(length);
        if node.target.contains(&0) {
            return Err(CensusDataError::Metadata);
        }

        node.kind = Some(CensusNodeKind::Symlink);
        self.check_capacity()
    }

    pub(super) fn retain_node_result(&mut self, index: usize, result: Result<(), CensusDataError>) -> bool {
        let failed = result.is_err();
        if failed && self.first_failed_node.is_none() { self.first_failed_node = Some(index); }
        if let Some(node) = self.records.get_mut(index) { node.outcome = Some(result); }
        !failed
    }

    pub(super) fn retain_preparation_failure(&mut self, error: CensusDataError) {
        if self.preparation_failure.is_none() { self.preparation_failure = Some(error); }
    }

    /// Performs the original inode post independently, including on action Err.
    pub(super) fn post_node(&mut self, index: usize) -> Result<(), CensusDataError> {
        let node = self.records.get_mut(index).ok_or(CensusDataError::Closed)?;
        if node.terminal_inode.is_none() {
            let original = node.readable.as_ref().and_then(|value| value.as_ref().ok()).map(AsFd::as_fd)
                .or_else(|| node.file.as_ref().and_then(|value| value.as_ref().ok()).map(|value| value.as_fd()))
                .or_else(|| node.symlink.as_ref().and_then(|value| value.as_ref().ok()).map(AsFd::as_fd))
                .or_else(|| node.resolved.as_ref().and_then(|value| value.as_ref().ok()).map(|value| value.as_fd()));
            if let Some(original) = original {
                node.terminal_inode = Some(rustix::fs::fstat(original));
            }
        }
        node.postcheck = Some(match (&node.inode[0], &node.terminal_inode) {
            (Some(Ok(before)), Some(Ok(after))) if !super::same_inode_state(before, after) => Err(CensusDataError::Changed),
            (_, Some(Err(_))) => Err(CensusDataError::NativeObservation),
            _ => Ok(()),
        });
        if node.postcheck.as_ref().is_some_and(Result::is_err) {
            if self.first_failed_node.is_none() { self.first_failed_node = Some(index); }
            Err(CensusDataError::Closed)
        } else {
            if matches!(node.outcome, Some(Ok(())))
                && !matches!(node.kind, Some(CensusNodeKind::Directory { .. }))
            {
                node.file = None;
                node.resolved = None;
                node.symlink = None;
            }
            Ok(())
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(error) = &self.preparation_failure { return Some(error); }
        if let Some(index) = self.first_failed_node {
            let node = self.records.get(index)?;
            // The specific subowner supplies its first cause. Later inode
            // posts cannot replace a completed metadata/content action Err.
            if let Some(error) = node.metadata.failure() {
                if matches!(error, CensusDataError::NativeObservation) {
                    if let Some(native) = node.metadata.native_failure() { return Some(native); }
                }
                return Some(error);
            }
            if let Some(error) = node.content.failure() { return Some(error); }
            if let Some(names) = &node.directory_names {
                if let Some(error) = names.failure() {
                    if matches!(error, CensusDataError::NativeObservation) {
                        if let Some(native) = names.native_failure() { return Some(native); }
                    }
                    return Some(error);
                }
            }
            if let Some(error) = node.resolved.as_ref().and_then(|value| value.as_ref().err()) { return Some(error); }
            if let Some(error) = node.file.as_ref().and_then(|value| value.as_ref().err()) { return Some(error); }
            if let Some(error) = node.inode[..2].iter().flatten().find_map(|value| value.as_ref().err()) { return Some(error); }
            if let Some(error) = node.readable.as_ref().and_then(|value| value.as_ref().err()) { return Some(error); }
            if let Some(error) = node.symlink.as_ref().and_then(|value| value.as_ref().err()) { return Some(error); }
            if let Some(error) = node.target_read.as_ref().and_then(|value| value.as_ref().err()) { return Some(error); }
            if let Some(error) = node.mount.as_ref().and_then(|value| value.as_ref().err()) { return Some(error); }
            if matches!(node.outcome, Some(Err(CensusDataError::NativeObservation))) {
                if let Some(error) = node.inode[2].as_ref().and_then(|value| value.as_ref().err()) {
                    return Some(error);
                }
            }
            if let Some(error) = node.outcome.as_ref().and_then(|value| value.as_ref().err()) { return Some(error); }
            if let Some(error) = node.inode[2].as_ref().and_then(|value| value.as_ref().err()) { return Some(error); }
            if let Some(error) = node.terminal_inode.as_ref().and_then(|value| value.as_ref().err()) { return Some(error); }
            if let Some(error) = node.postcheck.as_ref().and_then(|value| value.as_ref().err()) { return Some(error); }
        }
        if let Some(error) = self.root_mount.as_ref().and_then(|value| value.as_ref().err()) { return Some(error); }
        if let Some(error) = self.graph.as_ref().and_then(|value| value.as_ref().err()) { return Some(error); }
        self.outcome.as_ref().and_then(|value| value.as_ref().err())
            .map(|error| error as &(dyn std::error::Error + 'static))
    }

    /// Finalizes hardlink identities, then encodes descendants before parents.
    pub(crate) fn finalize(&mut self) -> Result<(), CensusDataError> {
        if self.complete || self.outcome.is_some() || self.first_failed_node.is_some() {
            return Err(CensusDataError::Closed);
        }
        self.outcome = Some(self.finalize_inner());
        match self.outcome.as_ref() {
            Some(Ok(())) => Ok(()),
            _ => Err(CensusDataError::Closed),
        }
    }

    fn finalize_inner(&mut self) -> Result<(), CensusDataError> {
        self.bind_hardlinks()?;
        self.derive_counters()?;
        for index in (0..self.records.len()).rev() {
            let Some(CensusNodeKind::Directory { entries, .. }) = &self.records[index].kind else { continue; };
            let mut encoded_entries = Vec::new();
            encoded_entries.try_reserve_exact(entries.len())?;
            for (name, child) in entries {
                encoded_entries.push(DirectoryEntry { name: name.clone(), node: self.canonical_node(*child)? });
            }
            let metadata = self.records[index].model.take().ok_or(CensusDataError::Closed)?;
            let directory = Directory::new(metadata, encoded_entries)?;
            let bytes = aos_sandbox_core::format::encode_directory(&directory);
            // The completed encoder buffer parks in the same arena before
            // descriptor/capacity checks. Opaque encoder prefixes are not an
            // allocation/preemption guarantee of this outer resident owner.
            let descriptor = self.arena.capture_object(PortableMediaType::Directory, bytes)?;
            let Some(CensusNodeKind::Directory { descriptor: slot, .. }) = &mut self.records[index].kind else {
                return Err(CensusDataError::Closed);
            };
            *slot = Some(descriptor);
            self.check_capacity()?;
        }
        let Some(CensusNodeKind::Directory { descriptor: Some(root), .. }) = &self.records[0].kind else {
            return Err(CensusDataError::Closed);
        };
        let mut features = Vec::new();
        features.try_reserve_exact(4)?;
        for namespace in [
            "aos.sandbox.metadata.posix-acl", "aos.sandbox.storage.snapshot-metadata-census",
            "aos.sandbox.symlink.absolute", "aos.sandbox.symlink.parent-escape",
        ] {
            features.push(FeatureRef::new(namespace, 1, 0).map_err(|_| CensusDataError::Metadata)?);
        }
        let tree = Tree::new(root.clone(), features)?;
        self.tree = Some(self.arena.capture_object(PortableMediaType::Tree, aos_sandbox_core::format::encode_tree(&tree))?);
        self.counters.canonical_object_bytes = u64::try_from(self.arena.canonical_bytes())
            .map_err(|_| CensusDataError::Capacity)?;
        self.counters.stored_content_bytes = u64::try_from(self.arena.stored_content_bytes()?)
            .map_err(|_| CensusDataError::Capacity)?;
        self.check_capacity()?;

        let mut bytes = Vec::new();
        bytes.try_reserve_exact(16 * 1024 * 1024)?;
        self.graph_writer_capacity = bytes.capacity();
        self.check_capacity()?;
        // The private writer is never a View/presentation capability. The
        // SAME graph engine validates every Content and directory object.
        let limits = aos_filesystem_view_core::TreeCompileLimits {
            object_bytes: 80 * 1024 * 1024, nodes: 4096, directory_entries: 4096, depth: 64,
            name_bytes: 1024 * 1024, symlink_bytes: 1024 * 1024, xattr_bytes: 8 * 1024 * 1024,
            xattrs: 16384, acl_entries: 65536, extents: 4096, hardlink_groups: 4096, hardlink_members: 4096,
            logical_bytes: 64 * 1024 * 1024, working_bytes: 32 * 1024 * 1024,
            index_bytes: 16 * 1024 * 1024, index_record_bytes: 16 * 1024 * 1024,
        };
        if self.capacity_bytes()?.checked_add(limits.working_bytes as usize)
            .is_none_or(|bytes| bytes > MAXIMUM_ARENA_BYTES)
        { return Err(CensusDataError::Capacity); }
        let descriptor = self.tree.as_ref().ok_or(CensusDataError::Closed)?;
        self.graph = Some(aos_filesystem_view_core::TreeCompiler::new(limits).validate_storage_census(
            &mut self.arena,
            aos_filesystem_view_core::IndexStaging::new(Cursor::new(bytes), limits.index_bytes, limits.index_record_bytes),
            descriptor, [0; 32],
        ));
        let summary = self.graph.as_ref().ok_or(CensusDataError::Closed)?
            .as_ref().map_err(|_| CensusDataError::Object)?.summary();
        let nodes = self.counters.directory_count.checked_add(self.counters.regular_entry_count)
            .and_then(|value| value.checked_add(self.counters.symlink_entry_count))
            .ok_or(CensusDataError::Capacity)?;
        if summary.nodes != nodes || summary.directories != self.counters.directory_count
            || summary.logical_bytes != self.counters.expanded_regular_logical_bytes
            || summary.name_bytes != self.counters.name_bytes
            || summary.xattr_bytes != self.counters.xattr_name_value_bytes
            || summary.hardlink_groups != self.counters.hardlink_group_count
        { return Err(CensusDataError::Object); }
        self.complete = true;
        Ok(())
    }

    fn canonical_node(&self, index: usize) -> Result<Node, CensusDataError> {
        let node = self.records.get(index).ok_or(CensusDataError::Closed)?;
        match &node.kind {
            Some(CensusNodeKind::Directory { descriptor: Some(descriptor), .. }) => Ok(Node::Directory(descriptor.clone())),
            Some(CensusNodeKind::File { content, group }) => Ok(Node::File(FileNode {
                metadata: node.model.as_ref().ok_or(CensusDataError::Closed)?.clone(),
                content: ContentLayout::whole(content.clone()), hardlink_group: *group,
            })),
            Some(CensusNodeKind::Symlink) => Ok(Node::Symlink(SymlinkNode::new(
                node.model.as_ref().ok_or(CensusDataError::Closed)?.clone(), node.target.clone(),
            )?)),
            _ => Err(CensusDataError::Closed),
        }
    }

    fn bind_hardlinks(&mut self) -> Result<(), CensusDataError> {
        for first in 0..self.records.len() {
            let Some(CensusNodeKind::File { content, group: None }) = &self.records[first].kind else { continue; };
            let before = *original_native(&self.records[first].inode[0])?;
            if before.st_nlink == 0 { return Err(CensusDataError::Metadata); }
            let content = ContentLayout::whole(content.clone());
            let metadata = self.records[first].model.as_ref().ok_or(CensusDataError::Closed)?;
            let mut members = Vec::new();
            let mut paths = Vec::new();
            for (index, node) in self.records.iter().enumerate() {
                let Some(CensusNodeKind::File { content: candidate, .. }) = &node.kind else { continue; };
                let current = original_native(&node.inode[0])?;
                if current.st_dev != before.st_dev || current.st_ino != before.st_ino { continue; }
                if !super::same_inode_state(&before, current)
                    || node.model.as_ref() != Some(metadata) || ContentLayout::whole(candidate.clone()) != content
                { return Err(CensusDataError::Changed); }
                members.try_reserve_exact(1)?;
                paths.try_reserve_exact(1)?;
                members.push(index);
                paths.push(node.portable_path.clone());
            }
            if u64::try_from(members.len()).map_err(|_| CensusDataError::Capacity)? != before.st_nlink {
                // Out-of-root aliases are not silently erased from a group.
                return Err(CensusDataError::Metadata);
            }
            if members.len() == 1 { continue; }
            paths.sort_by(|left, right| left.components().cmp(right.components()));
            let group = hardlink_group_digest(&paths, metadata, &content).map_err(|_| CensusDataError::Object)?;
            self.counters.hardlink_group_count = self.counters.hardlink_group_count.checked_add(1)
                .ok_or(CensusDataError::Capacity)?;
            self.counters.hardlink_member_count = self.counters.hardlink_member_count.checked_add(members.len() as u64)
                .ok_or(CensusDataError::Capacity)?;
            for index in members {
                let Some(CensusNodeKind::File { group: slot, .. }) = &mut self.records[index].kind else {
                    return Err(CensusDataError::Closed);
                };
                *slot = Some(group);
            }
        }
        Ok(())
    }

    fn derive_counters(&mut self) -> Result<(), CensusDataError> {
        for (index, node) in self.records.iter().enumerate() {
            let summary = node.metadata_summary.ok_or(CensusDataError::Closed)?;
            self.maximum_uid = self.maximum_uid.max(summary.maximum_uid);
            self.maximum_gid = self.maximum_gid.max(summary.maximum_gid);
            add_counter(&mut self.counters.xattr_count, summary.attribute_count, 16384)?;
            add_counter(&mut self.counters.xattr_name_value_bytes, summary.attribute_bytes, 8 * 1024 * 1024)?;
            add_counter(&mut self.counters.access_acl_entries, summary.access_acl_entries, 65536)?;
            add_counter(&mut self.counters.default_acl_entries, summary.default_acl_entries, 65536)?;
            if self.counters.access_acl_entries.checked_add(self.counters.default_acl_entries)
                .is_none_or(|count| count > 65536) { return Err(CensusDataError::Capacity); }
            if let Some(name) = node.portable_path.components().last() {
                add_counter(&mut self.counters.name_bytes, name.as_bytes().len() as u64, 1024 * 1024)?;
            }
            match &node.kind {
                Some(CensusNodeKind::Directory { .. }) => add_counter(&mut self.counters.directory_count, 1, 4096)?,
                Some(CensusNodeKind::Symlink) => add_counter(&mut self.counters.symlink_entry_count, 1, 4096)?,
                Some(CensusNodeKind::File { .. }) => {
                    let before = original_native(&node.inode[0])?;
                    let size = u64::try_from(before.st_size).map_err(|_| CensusDataError::Metadata)?;
                    add_counter(&mut self.counters.regular_entry_count, 1, 4096)?;
                    add_counter(&mut self.counters.expanded_regular_logical_bytes, size, 64 * 1024 * 1024)?;
                    let earlier = self.records[..index].iter().any(|candidate| {
                        matches!(candidate.kind, Some(CensusNodeKind::File { .. }))
                            && candidate.inode[0].as_ref().is_some_and(|result| result.as_ref().is_ok_and(|stat| {
                                stat.st_dev == before.st_dev && stat.st_ino == before.st_ino
                            }))
                    });
                    if !earlier {
                        add_counter(&mut self.counters.unique_regular_inode_count, 1, 4096)?;
                        add_counter(&mut self.counters.unique_regular_logical_bytes, size, 64 * 1024 * 1024)?;
                    }
                }
                None => return Err(CensusDataError::Closed),
            }
        }
        Ok(())
    }

    fn check_capacity(&self) -> Result<(), CensusDataError> {
        if self.capacity_bytes()? > MAXIMUM_ARENA_BYTES { return Err(CensusDataError::Capacity); }
        Ok(())
    }

    pub(crate) fn capacity_bytes(&self) -> Result<usize, CensusDataError> {
        let mut bytes = self.records.capacity().checked_mul(std::mem::size_of::<CensusNodeCapture>())
            .and_then(|value| value.checked_add(self.walk_name_capacity))
            .and_then(|value| value.checked_add(self.graph_writer_capacity))
            .ok_or(CensusDataError::Capacity)?;
        bytes = bytes.checked_add(self.directories.capacity()
            .checked_mul(std::mem::size_of::<CensusDirectoryFrame>())
            .ok_or(CensusDataError::Capacity)?).ok_or(CensusDataError::Capacity)?;
        bytes = bytes.checked_add(self.arena.capacity_bytes()?).ok_or(CensusDataError::Capacity)?;
        for node in &self.records {
            bytes = bytes.checked_add(node.path_capacity)
                .and_then(|value| value.checked_add(node.portable_path_capacity))
                .and_then(|value| value.checked_add(node.target.capacity()))
                .and_then(|value| value.checked_add(node.content.capacity_bytes()))
                .ok_or(CensusDataError::Capacity)?;
            bytes = bytes.checked_add(node.metadata.capacity_bytes()?).ok_or(CensusDataError::Capacity)?;
            if let Some(names) = &node.directory_names {
                bytes = bytes.checked_add(names.capacity_bytes()?).ok_or(CensusDataError::Capacity)?;
            }
            if let Some(CensusNodeKind::Directory { entries, .. }) = &node.kind {
                bytes = bytes.checked_add(entries.capacity().checked_mul(std::mem::size_of::<(PathName, usize)>())
                    .ok_or(CensusDataError::Capacity)?).ok_or(CensusDataError::Capacity)?;
            }
        }
        Ok(bytes)
    }
}

fn add_counter(counter: &mut u64, amount: u64, limit: u64) -> Result<(), CensusDataError> {
    *counter = counter.checked_add(amount).filter(|value| *value <= limit).ok_or(CensusDataError::Capacity)?;
    Ok(())
}

fn original_native<T>(result: &Option<Result<T, rustix::io::Errno>>) -> Result<&T, CensusDataError> {
    result.as_ref().ok_or(CensusDataError::Closed)?.as_ref().map_err(|_| CensusDataError::NativeObservation)
}

fn original_linux<T>(result: &Option<Result<T, aos_sandbox_linux::Error>>) -> Result<&T, CensusDataError> {
    result.as_ref().ok_or(CensusDataError::Closed)?.as_ref().map_err(|_| CensusDataError::NativeObservation)
}

fn census_bookend(result: &Option<Result<Stat, rustix::io::Errno>>, expected: &Stat) -> Result<(), CensusDataError> {
    match result {
        Some(Ok(after)) if super::same_inode_state(expected, after) => Ok(()),
        Some(Ok(_)) => Err(CensusDataError::Changed),
        Some(Err(_)) => Err(CensusDataError::NativeObservation),
        None => Err(CensusDataError::Closed),
    }
}

/// Owns one concrete census-data failure, never an omitted-metadata sentinel.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CensusDataError {
    #[error("census data exceeds its retained capacity")]
    Capacity,
    #[error("census data allocation failed: {0}")]
    Allocation(#[from] std::collections::TryReserveError),
    #[error("census object is absent or conflicts with its canonical descriptor")]
    Object,
    #[error("Linux ACL or capability data is unsupported or noncanonical")]
    Metadata,
    #[error("portable metadata validation failed: {0}")]
    PortableMetadata(#[from] aos_sandbox_core::model::tree::InvalidTreeModel),
    #[error("portable census name validation failed: {0}")]
    Name(#[from] aos_sandbox_core::InvalidPathName),
    // The concrete Errno stays in the metadata capture, including on a later
    // independent inode-bookend failure. This marker never replaces that loan.
    #[error("a retained native census observation failed")]
    NativeObservation,
    #[error("census data owner is closed after an incomplete capture")]
    Closed,
    #[error("an original census inode changed at its independent postcheck")]
    Changed,
    #[error("seed artifact input/output path or original mount is not confined")]
    ArtifactPath,
    #[error("a retained seed artifact output operation failed")]
    ArtifactOutput,
}

/// Borrows only the original inode or one checked name under its held parent.
///
/// The parent form exists for symlink metadata: Linux f*xattr does not accept
/// an O_PATH symlink descriptor. The generated proc path follows only the
/// held readable parent and l*xattr never follows its final component.
pub(crate) enum MetadataSubject<'fd> {
    Original(BorrowedFd<'fd>),
    Child { parent: BorrowedFd<'fd>, name: &'fd PathName },
}

struct AttributeObservation {
    name: Vec<u8>,
    value: Vec<u8>,
    sizes: [Option<Result<usize, rustix::io::Errno>>; 2],
}

/// Retains one inode's complete native metadata and independent postcheck.
///
/// Every native result and read prefix is parked before interpretation. Failed
/// captures cannot be repeated; the caller retains this owner in the traversal
/// reservoir and charges its actual capacities before visiting another inode.
#[derive(Default)]
pub(crate) struct CensusMetadataCapture {
    attempted: bool,
    complete: bool,
    proc_path: Option<CString>,
    proc_parent: CensusProcParentRoute,
    inode: [Option<Result<Stat, rustix::io::Errno>>; 2],
    list_sizes: [Option<Result<usize, rustix::io::Errno>>; 2],
    names: Vec<u8>,
    attributes: Vec<AttributeObservation>,
    pending_xattrs: Vec<Xattr>,
    pending_acl: Option<Acl>,
    model_bytes: usize,
    outcome: Option<Result<FilesystemMetadata, CensusDataError>>,
    postcheck: Option<Result<(), CensusDataError>>,
    maximum_uid: u32,
    maximum_gid: u32,
    access_acl_entries: u64,
    default_acl_entries: u64,
}

/// Refuses access without moving a failed capture's native cause or prefixes.
#[derive(Debug, thiserror::Error)]
#[error("the retained census metadata capture is incomplete")]
pub(crate) struct CensusMetadataRefusal;

/// Carries only sums derived from the retained complete metadata observation.
#[derive(Clone, Copy)]
pub(crate) struct CensusMetadataSummary {
    pub(crate) maximum_uid: u32,
    pub(crate) maximum_gid: u32,
    pub(crate) attribute_count: u64,
    pub(crate) attribute_bytes: u64,
    pub(crate) access_acl_entries: u64,
    pub(crate) default_acl_entries: u64,
}

/// Keeps a regular inode's exact read prefix and independent native bookends.
///
/// The physical walker retains the actual `ResolvedFile`; this child borrows
/// it and uses the existing positioned reader/EOF engine without duplication.
/// The readonly original mount and the caller's same clock/subject checks remain
/// separate prerequisites. This does not universally preempt a kernel read.
#[derive(Default)]
pub(crate) struct CensusContentCapture {
    attempted: bool,
    complete: bool,
    inode: [Option<Result<Stat, rustix::io::Errno>>; 2],
    bytes: Vec<u8>,
    read: Option<Result<(), ExactReadFailure>>,
    outcome: Option<Result<(), CensusDataError>>,
    postcheck: Option<Result<(), CensusDataError>>,
    extent: Option<usize>,
}

impl CensusContentCapture {
    pub(crate) fn capture(
        &mut self,
        original: &ResolvedFile,
        expected: &Stat,
    ) -> Result<(), CensusMetadataRefusal> {
        if self.attempted {
            return Err(CensusMetadataRefusal);
        }
        self.attempted = true;
        self.outcome = Some(self.capture_inner(original, expected));

        // A failed exact read retains its real errno before this independent
        // stat. No healthy accessor or retry is possible after either failure.
        self.inode[1] = Some(rustix::fs::fstat(original.as_fd()));
        self.postcheck = Some(match self.inode[1].as_ref() {
            Some(Ok(after)) if super::same_inode_state(expected, after) => Ok(()),
            Some(Ok(_)) => Err(CensusDataError::Changed),
            Some(Err(_)) => Err(CensusDataError::NativeObservation),
            None => Err(CensusDataError::Closed),
        });
        self.complete = matches!(self.outcome, Some(Ok(())))
            && matches!(self.postcheck, Some(Ok(())));
        if self.complete { Ok(()) } else { Err(CensusMetadataRefusal) }
    }

    fn capture_inner(&mut self, original: &ResolvedFile, expected: &Stat) -> Result<(), CensusDataError> {
        self.inode[0] = Some(rustix::fs::fstat(original.as_fd()));
        let before = self.inode[0].as_ref().ok_or(CensusDataError::Closed)?
            .as_ref().map_err(|_| CensusDataError::NativeObservation)?;
        if !super::same_inode_state(expected, before)
            || rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::RegularFile
        {
            return Err(CensusDataError::Metadata);
        }

        // Allocation derives only from the admitted original extent, not a
        // later metadata sample, caller quantity or declared logical maximum.
        let extent = usize::try_from(expected.st_size).map_err(|_| CensusDataError::Capacity)?;
        if extent > super::MAXIMUM_FILE_BYTES {
            return Err(CensusDataError::Capacity);
        }
        self.extent = Some(extent);
        self.bytes.try_reserve_exact(extent)?;
        self.bytes.resize(extent, 0);
        self.read = Some(read_exact_positioned_census_retaining_cause(original.as_fd(), &mut self.bytes));
        if self.read.as_ref().is_some_and(Result::is_err) {
            return Err(CensusDataError::NativeObservation);
        }
        Ok(())
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let Some(Err(error)) = &self.outcome else {
            return self.inode[1].as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static))
                .or_else(|| self.postcheck.as_ref().and_then(|result| result.as_ref().err())
                    .map(|error| error as &(dyn std::error::Error + 'static)));
        };
        if matches!(error, CensusDataError::NativeObservation) {
            if let Some(error) = self.inode[0].as_ref().and_then(|result| result.as_ref().err()) {
                return Some(error);
            }
            if let Some(error) = self.read.as_ref().and_then(|result| result.as_ref().err()) {
                return Some(error);
            }
        }
        Some(error)
    }

    pub(crate) fn postcheck_debt(&self) -> Option<&rustix::io::Errno> {
        self.inode[1].as_ref().and_then(|result| result.as_ref().err())
    }

    pub(crate) fn bytes(&self) -> Result<&[u8], CensusMetadataRefusal> {
        if !self.complete {
            return Err(CensusMetadataRefusal);
        }
        Ok(&self.bytes)
    }

    pub(crate) fn capacity_bytes(&self) -> usize { self.bytes.capacity() }

    fn transfer_bytes(&mut self) -> Result<Vec<u8>, CensusMetadataRefusal> {
        self.bytes()?;
        self.complete = false;
        Ok(std::mem::take(&mut self.bytes))
    }
}

impl CensusMetadataCapture {
    pub(crate) fn capture(
        &mut self,
        subject: MetadataSubject<'_>,
        expected: &Stat,
    ) -> Result<(), CensusMetadataRefusal> {
        if self.attempted {
            return Err(CensusMetadataRefusal);
        }
        // An unwind cannot leave the capture apparently reusable or healthy.
        self.attempted = true;
        self.outcome = Some(self.capture_inner(&subject, expected));

        // This native bookend is independent of the action result. A native
        // read error remains first; a later stat error remains separate debt.
        self.inode[1] = Some(subject.stat());
        self.postcheck = Some(census_bookend(&self.inode[1], expected));
        self.proc_parent.postcheck(&subject,
            matches!(self.outcome, Some(Ok(_))) && matches!(self.postcheck, Some(Ok(()))));
        self.complete = matches!(self.outcome, Some(Ok(_)))
            && matches!(self.postcheck, Some(Ok(())))
            && self.proc_parent.is_current();
        if self.complete { Ok(()) } else { Err(CensusMetadataRefusal) }
    }

    fn capture_inner(
        &mut self,
        subject: &MetadataSubject<'_>,
        expected: &Stat,
    ) -> Result<FilesystemMetadata, CensusDataError> {
        self.inode[0] = Some(subject.stat());
        let before = self.inode[0].as_ref().ok_or(CensusDataError::Closed)?
            .as_ref().map_err(|_| CensusDataError::NativeObservation)?;
        if !super::same_inode_state(expected, before) {
            return Err(CensusDataError::Metadata);
        }

        self.proc_path = self.proc_parent.prepare(subject)?;
        self.list_sizes[0] = Some(subject.list(self.proc_path.as_deref(), &mut []));
        let length = retained_size(&self.list_sizes[0])?;
        if length > MAXIMUM_XATTR_LIST_BYTES {
            return Err(CensusDataError::Capacity);
        }
        self.names.try_reserve_exact(length)?;
        self.names.resize(length, 0);
        self.list_sizes[1] = Some(subject.list(self.proc_path.as_deref(), &mut self.names));
        if retained_size(&self.list_sizes[1])? != length {
            return Err(CensusDataError::Metadata);
        }

        // Native list order is unspecified. Byte sorting is the sole portable
        // name order; duplicates, missing terminators and empty names refuse.
        let mut offset = 0;
        while offset < self.names.len() {
            let suffix = &self.names[offset..];
            let end = suffix.iter().position(|byte| *byte == 0)
                .ok_or(CensusDataError::Metadata)?;
            if end == 0 || end > 255 || self.attributes.len() == MAXIMUM_XATTRS {
                return Err(CensusDataError::Metadata);
            }
            self.attributes.try_reserve_exact(1)?;
            let mut name = Vec::new();
            name.try_reserve_exact(end)?;
            name.extend_from_slice(&suffix[..end]);
            self.attributes.push(AttributeObservation {
                name, value: Vec::new(), sizes: [None, None],
            });
            offset = offset.checked_add(end + 1).ok_or(CensusDataError::Capacity)?;
        }
        self.attributes.sort_by(|left, right| left.name.cmp(&right.name));
        if self.attributes.windows(2).any(|pair| pair[0].name == pair[1].name) {
            return Err(CensusDataError::Metadata);
        }

        self.pending_xattrs.try_reserve_exact(self.attributes.len())?;
        self.model_bytes = self.pending_xattrs.capacity()
            .checked_mul(std::mem::size_of::<Xattr>()).ok_or(CensusDataError::Capacity)?;
        let mut attribute_bytes = 0_usize;
        self.maximum_uid = expected.st_uid;
        self.maximum_gid = expected.st_gid;
        let directory = rustix::fs::FileType::from_raw_mode(expected.st_mode)
            == rustix::fs::FileType::Directory;
        for attribute in &mut self.attributes {
            let name = std::ffi::OsStr::from_bytes(&attribute.name);
            attribute.sizes[0] = Some(subject.get(self.proc_path.as_deref(), name, &mut []));
            let size = retained_size(&attribute.sizes[0])?;
            attribute_bytes = attribute_bytes.checked_add(attribute.name.len())
                .and_then(|value| value.checked_add(size))
                .filter(|value| *value <= MAXIMUM_XATTR_BYTES)
                .ok_or(CensusDataError::Capacity)?;
            if size > MAXIMUM_XATTR_VALUE_BYTES {
                return Err(CensusDataError::Capacity);
            }
            attribute.value.try_reserve_exact(size)?;
            attribute.value.resize(size, 0);
            attribute.sizes[1] = Some(subject.get(
                self.proc_path.as_deref(), name, &mut attribute.value,
            ));
            if retained_size(&attribute.sizes[1])? != size {
                return Err(CensusDataError::Metadata);
            }

            match attribute.name.as_slice() {
                b"system.posix_acl_access" => {
                    let observation = decode_linux_acl(
                        &attribute.value, AclDisposition::Access, directory,
                    )?;
                    self.maximum_uid = self.maximum_uid.max(observation.maximum_uid);
                    self.maximum_gid = self.maximum_gid.max(observation.maximum_gid);
                    self.access_acl_entries = observation.acl.entries().len() as u64;
                    self.model_bytes = self.model_bytes.checked_add(observation.capacity_bytes)
                        .ok_or(CensusDataError::Capacity)?;
                    self.pending_acl = Some(observation.acl);
                }
                b"system.posix_acl_default" => {
                    let observation = decode_linux_acl(
                        &attribute.value, AclDisposition::Default, directory,
                    )?;
                    self.maximum_uid = self.maximum_uid.max(observation.maximum_uid);
                    self.maximum_gid = self.maximum_gid.max(observation.maximum_gid);
                    self.default_acl_entries = observation.acl.entries().len() as u64;
                }
                b"security.capability" => {
                    self.maximum_uid = self.maximum_uid.max(capability_root_id(&attribute.value)?);
                }
                _ => {}
            }
            // Raw access/default ACLs and capability bytes remain in xattrs;
            // the semantic ACL is additional checked metadata, not erasure.
            let mut canonical_name = Vec::new();
            canonical_name.try_reserve_exact(attribute.name.len())?;
            canonical_name.extend_from_slice(&attribute.name);
            let mut canonical_value = Vec::new();
            canonical_value.try_reserve_exact(attribute.value.len())?;
            canonical_value.extend_from_slice(&attribute.value);
            self.model_bytes = self.model_bytes.checked_add(canonical_name.capacity())
                .and_then(|value| value.checked_add(canonical_value.capacity()))
                .ok_or(CensusDataError::Capacity)?;
            self.pending_xattrs.push(Xattr::new(canonical_name, canonical_value)?);
        }
        let mode = u16::try_from(expected.st_mode & 0o7777)
            .map_err(|_| CensusDataError::Metadata)?;
        let nanos = u32::try_from(expected.st_mtime_nsec)
            .map_err(|_| CensusDataError::Metadata)?;
        FilesystemMetadata::new(
            mode, expected.st_uid, expected.st_gid, expected.st_mtime, nanos,
            std::mem::take(&mut self.pending_xattrs), self.pending_acl.take(),
        ).map_err(CensusDataError::from)
    }

    pub(crate) fn metadata(&self) -> Result<&FilesystemMetadata, CensusMetadataRefusal> {
        if !self.complete {
            return Err(CensusMetadataRefusal);
        }
        self.outcome.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CensusMetadataRefusal)
    }

    pub(crate) fn summary(&self) -> Result<CensusMetadataSummary, CensusMetadataRefusal> {
        self.metadata()?;
        let mut attribute_bytes = 0_u64;
        for attribute in &self.attributes {
            let name = u64::try_from(attribute.name.len()).map_err(|_| CensusMetadataRefusal)?;
            let value = u64::try_from(attribute.value.len()).map_err(|_| CensusMetadataRefusal)?;
            attribute_bytes = attribute_bytes.checked_add(name)
                .and_then(|bytes| bytes.checked_add(value)).ok_or(CensusMetadataRefusal)?;
        }
        Ok(CensusMetadataSummary {
            maximum_uid: self.maximum_uid,
            maximum_gid: self.maximum_gid,
            attribute_count: u64::try_from(self.attributes.len()).map_err(|_| CensusMetadataRefusal)?,
            attribute_bytes,
            access_acl_entries: self.access_acl_entries,
            default_acl_entries: self.default_acl_entries,
        })
    }

    /// Borrows the original action failure, without moving its native owner.
    pub(crate) fn failure(&self) -> Option<&CensusDataError> {
        self.outcome.as_ref().and_then(|result| result.as_ref().err())
            .or_else(|| self.postcheck.as_ref().and_then(|result| result.as_ref().err()))
            .or_else(|| self.proc_parent.debt.as_ref().and_then(|result| result.as_ref().err()))
    }

    /// Borrows the first actual errno in observation order, including posts.
    pub(crate) fn native_failure(&self) -> Option<&rustix::io::Errno> {
        self.inode[0].as_ref().and_then(|result| result.as_ref().err())
            .or_else(|| self.proc_parent.initial_native_failure())
            .or_else(|| self.list_sizes.iter().flatten().find_map(|result| result.as_ref().err()))
            .or_else(|| self.attributes.iter().find_map(|attribute| {
                attribute.sizes.iter().flatten().find_map(|result| result.as_ref().err())
            }))
            .or_else(|| self.inode[1].as_ref().and_then(|result| result.as_ref().err()))
            .or_else(|| self.proc_parent.final_native_failure())
    }

    pub(crate) fn capacity_bytes(&self) -> Result<usize, CensusDataError> {
        let mut bytes = self.names.capacity().checked_add(
            self.attributes.capacity().checked_mul(std::mem::size_of::<AttributeObservation>())
                .ok_or(CensusDataError::Capacity)?,
        ).ok_or(CensusDataError::Capacity)?;
        if let Some(path) = &self.proc_path {
            bytes = bytes.checked_add(path.as_bytes_with_nul().len())
                .ok_or(CensusDataError::Capacity)?;
        }
        for attribute in &self.attributes {
            bytes = bytes.checked_add(attribute.name.capacity())
                .and_then(|value| value.checked_add(attribute.value.capacity()))
                .ok_or(CensusDataError::Capacity)?;
        }
        // These capacities were observed before buffers moved through Core's
        // private model. Slice lengths are not physical allocation evidence.
        bytes.checked_add(self.model_bytes).ok_or(CensusDataError::Capacity)
    }

    fn transfer_metadata(&mut self) -> Result<FilesystemMetadata, CensusMetadataRefusal> {
        self.metadata()?;
        self.complete = false;
        match self.outcome.take() {
            Some(Ok(metadata)) => Ok(metadata),
            _ => Err(CensusMetadataRefusal),
        }
    }
}

impl MetadataSubject<'_> {
    fn stat(&self) -> Result<Stat, rustix::io::Errno> {
        match self {
            Self::Original(original) => rustix::fs::fstat(original.as_fd()),
            Self::Child { parent, name } => rustix::fs::statat(
                parent.as_fd(), std::ffi::OsStr::from_bytes(name.as_bytes()),
                AtFlags::SYMLINK_NOFOLLOW,
            ),
        }
    }

    fn list(
        &self,
        path: Option<&std::ffi::CStr>,
        bytes: &mut [u8],
    ) -> Result<usize, rustix::io::Errno> {
        match self {
            Self::Original(original) => rustix::fs::flistxattr(original.as_fd(), bytes),
            Self::Child { .. } => match path {
                Some(path) => rustix::fs::llistxattr(path, bytes),
                None => Err(rustix::io::Errno::INVAL),
            },
        }
    }

    fn get(
        &self,
        path: Option<&std::ffi::CStr>,
        name: &std::ffi::OsStr,
        bytes: &mut [u8],
    ) -> Result<usize, rustix::io::Errno> {
        match self {
            Self::Original(original) => rustix::fs::fgetxattr(original.as_fd(), name, bytes),
            Self::Child { .. } => match path {
                Some(path) => rustix::fs::lgetxattr(path, name, bytes),
                None => Err(rustix::io::Errno::INVAL),
            },
        }
    }
}

// Only symlink xattrs need a pathname. This fixed self-proc route is checked
// against the actual readable parent, not accepted because its string looks
// familiar. Its two returned descriptors remain resident on failure/unwind.
#[derive(Default)]
struct CensusProcParentRoute {
    directory: Option<Result<OwnedFd, rustix::io::Errno>>,
    filesystem: Option<Result<rustix::fs::StatFs, rustix::io::Errno>>,
    alias: Option<Result<OwnedFd, rustix::io::Errno>>,
    parent_inode: [Option<Result<Stat, rustix::io::Errno>>; 2],
    alias_inode: [Option<Result<Stat, rustix::io::Errno>>; 2],
    debt: Option<Result<(), CensusDataError>>,
}

impl CensusProcParentRoute {
    fn prepare(&mut self, subject: &MetadataSubject<'_>) -> Result<Option<CString>, CensusDataError> {
        let MetadataSubject::Child { parent, name } = subject else {
            return Ok(None);
        };

        self.directory = Some(rustix::fs::open(
            "/proc/self/fd",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        let directory = original_native(&self.directory)?;
        self.filesystem = Some(rustix::fs::fstatfs(directory.as_fd()));
        if original_native(&self.filesystem)?.f_type as u64 != 0x9fa0 {
            return Err(CensusDataError::Metadata);
        }

        self.parent_inode[0] = Some(rustix::fs::fstat(parent.as_fd()));
        let expected = *original_native(&self.parent_inode[0])?;

        // Following this one procfs magic link is intentional. The exact
        // returned inode must equal the existing held parent before l*xattr.
        let component = parent.as_raw_fd().to_string();
        self.alias = Some(rustix::fs::openat(
            directory.as_fd(),
            component.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        let alias = original_native(&self.alias)?;
        self.alias_inode[0] = Some(rustix::fs::fstat(alias.as_fd()));
        if !super::same_inode_state(&expected, original_native(&self.alias_inode[0])?) {
            return Err(CensusDataError::Changed);
        }

        // The intermediate proc directory is itself held. The final name is
        // a validated component and l*xattr never follows that final symlink.
        let mut path = format!("/proc/self/fd/{}/{}/", directory.as_raw_fd(), component)
            .into_bytes();
        path.try_reserve_exact(name.as_bytes().len())?;
        path.extend_from_slice(name.as_bytes());
        if path.len() > 4096 {
            return Err(CensusDataError::Capacity);
        }

        CString::new(path).map(Some).map_err(|_| CensusDataError::Metadata)
    }

    fn postcheck(&mut self, subject: &MetadataSubject<'_>, action_succeeded: bool) {
        let MetadataSubject::Child { parent, .. } = subject else {
            return;
        };

        // Posts run independently even when opening or reading metadata failed.
        self.parent_inode[1] = Some(rustix::fs::fstat(parent.as_fd()));
        if let Some(Ok(alias)) = &self.alias {
            self.alias_inode[1] = Some(rustix::fs::fstat(alias.as_fd()));
        }
        self.debt = Some(self.require_postcheck());

        if action_succeeded && matches!(self.debt, Some(Ok(()))) {
            self.alias = None;
            self.directory = None;
        }
    }

    fn require_postcheck(&self) -> Result<(), CensusDataError> {
        let expected = original_native(&self.parent_inode[0])?;
        if !super::same_inode_state(expected, original_native(&self.parent_inode[1])?) {
            return Err(CensusDataError::Changed);
        }
        if self.alias.is_some() {
            if !super::same_inode_state(expected, original_native(&self.alias_inode[1])?) {
                return Err(CensusDataError::Changed);
            }
        }
        Ok(())
    }

    fn is_current(&self) -> bool {
        self.debt.as_ref().is_none_or(|result| result.is_ok())
    }

    fn initial_native_failure(&self) -> Option<&rustix::io::Errno> {
        self.directory.as_ref().and_then(|result| result.as_ref().err())
            .or_else(|| self.filesystem.as_ref().and_then(|result| result.as_ref().err()))
            .or_else(|| self.parent_inode[0].as_ref().and_then(|result| result.as_ref().err()))
            .or_else(|| self.alias.as_ref().and_then(|result| result.as_ref().err()))
            .or_else(|| self.alias_inode[0].as_ref().and_then(|result| result.as_ref().err()))
    }

    fn final_native_failure(&self) -> Option<&rustix::io::Errno> {
        self.parent_inode[1].as_ref().and_then(|result| result.as_ref().err())
            .or_else(|| self.alias_inode[1].as_ref().and_then(|result| result.as_ref().err()))
    }
}

fn retained_size(
    result: &Option<Result<usize, rustix::io::Errno>>,
) -> Result<usize, CensusDataError> {
    match result {
        Some(Ok(size)) => Ok(*size),
        Some(Err(_)) => Err(CensusDataError::NativeObservation),
        None => Err(CensusDataError::Closed),
    }
}

struct DirectoryNameObservation {
    name: PathName,
    capacity: usize,
}

/// Keeps getdents scratch, accepted names and actual native failure resident.
///
/// RawDir borrows the containing walker's original readable descriptor. It
/// does not consume or duplicate it. Scratch is prepared before that walker's
/// open; neither an EOF nor this DATA value proves the caller's origin clock.
pub(crate) struct CensusDirectoryNames {
    attempted: bool,
    complete: bool,
    scratch: Vec<MaybeUninit<u8>>,
    names: Vec<DirectoryNameObservation>,
    pending_name: Vec<u8>,
    stat: [Option<Result<Stat, rustix::io::Errno>>; 2],
    read_failure: Option<rustix::io::Errno>,
    outcome: Option<Result<(), CensusDataError>>,
    postcheck: Option<Result<(), CensusDataError>>,
    name_bytes: usize,
}

#[derive(Debug, thiserror::Error)]
#[error("the retained census directory enumeration is incomplete")]
pub(crate) struct CensusDirectoryRefusal;

impl CensusDirectoryNames {
    pub(crate) fn prepare() -> Result<Self, CensusDataError> {
        let mut scratch = Vec::new();
        scratch.try_reserve_exact(64 * 1024)?;
        scratch.resize_with(64 * 1024, MaybeUninit::uninit);
        Ok(Self {
            attempted: false,
            complete: false,
            scratch,
            names: Vec::new(),
            pending_name: Vec::new(),
            stat: [None, None],
            read_failure: None,
            outcome: None,
            postcheck: None,
            name_bytes: 0,
        })
    }

    pub(crate) fn capture(
        &mut self,
        original: BorrowedFd<'_>,
        expected: &Stat,
    ) -> Result<(), CensusDirectoryRefusal> {
        if self.attempted {
            return Err(CensusDirectoryRefusal);
        }
        self.attempted = true;
        self.outcome = Some(self.capture_inner(original, expected));
        self.stat[1] = Some(rustix::fs::fstat(original));
        self.postcheck = Some(census_bookend(&self.stat[1], expected));
        self.complete = matches!(self.outcome, Some(Ok(())))
            && matches!(self.postcheck, Some(Ok(())));
        if self.complete { Ok(()) } else { Err(CensusDirectoryRefusal) }
    }

    fn capture_inner(
        &mut self,
        original: BorrowedFd<'_>,
        expected: &Stat,
    ) -> Result<(), CensusDataError> {
        self.stat[0] = Some(rustix::fs::fstat(original));
        let before = self.stat[0].as_ref().ok_or(CensusDataError::Closed)?
            .as_ref().map_err(|_| CensusDataError::NativeObservation)?;
        if !super::same_inode_state(expected, before)
            || rustix::fs::FileType::from_raw_mode(before.st_mode)
                != rustix::fs::FileType::Directory
        {
            return Err(CensusDataError::Metadata);
        }

        let mut directory = rustix::fs::RawDir::new(original, &mut self.scratch);
        while let Some(result) = directory.next() {
            let entry = match result {
                Ok(entry) => entry,
                Err(error) => {
                    self.read_failure = Some(error);
                    return Err(CensusDataError::NativeObservation);
                }
            };
            let bytes = entry.file_name().to_bytes();
            if matches!(bytes, b"." | b"..") {
                continue;
            }
            if self.names.len() == super::MAXIMUM_NODES {
                return Err(CensusDataError::Capacity);
            }
            self.name_bytes = self.name_bytes.checked_add(bytes.len())
                .filter(|count| *count <= 1024 * 1024).ok_or(CensusDataError::Capacity)?;
            self.pending_name.try_reserve_exact(bytes.len())?;
            self.pending_name.extend_from_slice(bytes);
            // Native d_type and inode are not a child-kind authority. The
            // walker separately opens/checks the exact beneath-root original.
            PathName::validate(&self.pending_name)?;
            self.names.try_reserve_exact(1)?;
            let capacity = self.pending_name.capacity();
            let name = PathName::new(std::mem::take(&mut self.pending_name))?;
            self.names.push(DirectoryNameObservation { name, capacity });
        }
        self.names.sort_by(|left, right| left.name.cmp(&right.name));
        if self.names.windows(2).any(|pair| pair[0].name == pair[1].name) {
            return Err(CensusDataError::Metadata);
        }
        Ok(())
    }

    pub(crate) fn names(
        &self,
    ) -> Result<impl ExactSizeIterator<Item = &PathName>, CensusDirectoryRefusal> {
        if !self.complete {
            return Err(CensusDirectoryRefusal);
        }
        Ok(self.names.iter().map(|entry| &entry.name))
    }

    pub(crate) fn failure(&self) -> Option<&CensusDataError> {
        self.outcome.as_ref().and_then(|result| result.as_ref().err())
            .or_else(|| self.postcheck.as_ref().and_then(|result| result.as_ref().err()))
    }

    pub(crate) fn native_failure(&self) -> Option<&rustix::io::Errno> {
        self.stat[0].as_ref().and_then(|result| result.as_ref().err())
            .or(self.read_failure.as_ref())
            .or_else(|| self.stat[1].as_ref().and_then(|result| result.as_ref().err()))
    }

    pub(crate) fn capacity_bytes(&self) -> Result<usize, CensusDataError> {
        let mut bytes = self.scratch.capacity().checked_add(self.pending_name.capacity())
            .and_then(|value| value.checked_add(self.names.capacity()
                .checked_mul(std::mem::size_of::<DirectoryNameObservation>())?))
            .ok_or(CensusDataError::Capacity)?;
        for entry in &self.names {
            bytes = bytes.checked_add(entry.capacity).ok_or(CensusDataError::Capacity)?;
        }
        Ok(bytes)
    }
}

struct CanonicalObject {
    descriptor: ObjectDescriptor,
    media_capacity: usize,
    bytes: Vec<u8>,
}

/// Retains originals without copying whole objects in the graph source adapter.
#[derive(Default)]
pub(crate) struct CensusObjectArena {
    objects: Vec<CanonicalObject>,
    pending: Option<Vec<u8>>,
    pending_descriptor: Option<ObjectDescriptor>,
    pending_media_capacity: usize,
    canonical_bytes: usize,
    closed: bool,
}

impl CensusObjectArena {
    /// Parks a completed canonical buffer before any descriptor/capacity checks.
    ///
    /// On failure the pending buffer remains resident and the arena cannot be
    /// re-entered. A descriptor collision is successful only after exact byte
    /// equality; equal physical content is not treated as inode aliasing.
    pub(crate) fn capture_object(
        &mut self,
        kind: PortableMediaType,
        bytes: Vec<u8>,
    ) -> Result<ObjectDescriptor, CensusDataError> {
        if self.closed || self.pending.is_some() || self.pending_descriptor.is_some() {
            return Err(CensusDataError::Closed);
        }
        self.closed = true;
        self.pending = Some(bytes);
        let original = self.pending.as_ref().ok_or(CensusDataError::Closed)?;
        if original.len() > MAXIMUM_CANONICAL_BYTES
            || self.capacity_bytes()? > MAXIMUM_ARENA_BYTES
        {
            return Err(CensusDataError::Capacity);
        }

        // Keep the actual String capacity before moving it through the sole
        // MediaType validator. Its allocation is not guessed from byte length.
        let mut media_name = String::new();
        media_name.try_reserve_exact(kind.as_str().len())?;
        self.pending_media_capacity = media_name.capacity();
        media_name.push_str(kind.as_str());
        let media = MediaType::new(media_name).map_err(|_| CensusDataError::Object)?;
        self.pending_descriptor = Some(descriptor_for_bytes(media, original));
        let descriptor = self.pending_descriptor.as_ref().ok_or(CensusDataError::Closed)?;
        if let Some(existing) = self.objects.iter().find(|object| &object.descriptor == descriptor) {
            if existing.bytes != *original {
                return Err(CensusDataError::Object);
            }
            let returned = descriptor.clone();
            self.pending = None;
            self.pending_descriptor = None;
            self.pending_media_capacity = 0;
            self.closed = false;
            return Ok(returned);
        }

        let next = self.canonical_bytes.checked_add(original.len())
            .filter(|bytes| *bytes <= MAXIMUM_CANONICAL_BYTES)
            .ok_or(CensusDataError::Capacity)?;
        if self.objects.len() == MAXIMUM_OBJECTS {
            return Err(CensusDataError::Capacity);
        }
        let retained = self.capacity_bytes()?;
        let growth = std::mem::size_of::<CanonicalObject>();
        if retained.checked_add(growth).is_none_or(|bytes| bytes > MAXIMUM_ARENA_BYTES) {
            return Err(CensusDataError::Capacity);
        }
        self.objects.try_reserve_exact(1)?;
        // The allocator may round capacity upward. The actual increased
        // container and original pending bytes are still resident on refusal.
        if self.capacity_bytes()? > MAXIMUM_ARENA_BYTES {
            return Err(CensusDataError::Capacity);
        }
        // Any opaque clone allocation precedes the move of either original.
        // The caller separately charges the returned comparison descriptor.
        let returned = self.pending_descriptor.as_ref()
            .ok_or(CensusDataError::Closed)?.clone();
        let bytes = self.pending.take().ok_or(CensusDataError::Closed)?;
        let descriptor = self.pending_descriptor.take().ok_or(CensusDataError::Closed)?;
        let media_capacity = self.pending_media_capacity;
        self.pending_media_capacity = 0;
        self.objects.push(CanonicalObject { descriptor, media_capacity, bytes });
        self.canonical_bytes = next;
        self.closed = false;
        Ok(returned)
    }

    pub(crate) fn capacity_bytes(&self) -> Result<usize, CensusDataError> {
        let mut bytes = self.objects.capacity()
            .checked_mul(std::mem::size_of::<CanonicalObject>())
            .ok_or(CensusDataError::Capacity)?;
        for object in &self.objects {
            bytes = bytes.checked_add(object.bytes.capacity())
                .and_then(|value| value.checked_add(object.media_capacity))
                .ok_or(CensusDataError::Capacity)?;
        }
        if let Some(pending) = &self.pending {
            bytes = bytes.checked_add(pending.capacity()).ok_or(CensusDataError::Capacity)?;
        }
        bytes.checked_add(self.pending_media_capacity).ok_or(CensusDataError::Capacity)
    }

    pub(crate) const fn canonical_bytes(&self) -> usize {
        self.canonical_bytes
    }

    fn stored_content_bytes(&self) -> Result<usize, CensusDataError> {
        self.objects.iter().filter(|object| object.descriptor.media_type().as_str() == PortableMediaType::Content.as_str())
            .try_fold(0_usize, |sum, object| sum.checked_add(object.bytes.len()).ok_or(CensusDataError::Capacity))
    }

    pub(crate) fn objects(&self) -> Result<impl ExactSizeIterator<Item = (&ObjectDescriptor, &[u8])>, CensusDataError> {
        if self.closed || self.pending.is_some() || self.pending_descriptor.is_some() {
            return Err(CensusDataError::Closed);
        }
        Ok(self.objects.iter().map(|object| (&object.descriptor, object.bytes.as_slice())))
    }
}

impl ObjectSource for CensusObjectArena {
    type Error = CensusDataError;
    type Reader<'source> = Cursor<&'source [u8]>;

    fn open<'source>(
        &'source mut self,
        descriptor: &ObjectDescriptor,
    ) -> Result<Self::Reader<'source>, Self::Error> {
        if self.closed || self.pending.is_some() || self.pending_descriptor.is_some() {
            return Err(CensusDataError::Closed);
        }
        let object = self.objects.iter().find(|object| &object.descriptor == descriptor)
            .ok_or(CensusDataError::Object)?;
        // The sole compiler performs exact EOF/digest checks on this borrowed
        // original; the adapter allocates neither a copy nor a new authority.
        Ok(Cursor::new(object.bytes.as_slice()))
    }
}

/// Distinguishes native access metadata from directory inheritance DATA.
#[derive(Clone, Copy)]
pub(crate) enum AclDisposition {
    Access,
    Default,
}

pub(crate) struct LinuxAclObservation {
    pub(crate) acl: Acl,
    pub(crate) maximum_uid: u32,
    pub(crate) maximum_gid: u32,
    pub(crate) capacity_bytes: usize,
}

/// Decodes the pinned Linux LE version2 layout into the sole Core ACL model.
///
/// Both dispositions require complete object/mask semantics. Default ACLs
/// are allowed only on a directory and do not claim equality to its own mode;
/// access ACL/mode equality is checked by the existing graph validator.
pub(crate) fn decode_linux_acl(
    bytes: &[u8],
    disposition: AclDisposition,
    directory: bool,
) -> Result<LinuxAclObservation, CensusDataError> {
    if bytes.len() < 4 || (bytes.len() - 4) % 8 != 0 || le_u32(bytes, 0)? != 2
        || matches!(disposition, AclDisposition::Default) && !directory
    {
        return Err(CensusDataError::Metadata);
    }
    let count = (bytes.len() - 4) / 8;
    if !(3..=MAXIMUM_ACL_ENTRIES).contains(&count) {
        return Err(CensusDataError::Metadata);
    }
    let mut entries = Vec::new();
    entries.try_reserve_exact(count)?;
    let mut maximum_uid = 0;
    let mut maximum_gid = 0;
    let mut objects = [false; 3];
    let mut named = false;
    let mut mask = false;
    for index in 0..count {
        let offset = 4 + index * 8;
        let tag = le_u16(bytes, offset)?;
        let permissions = u8::try_from(le_u16(bytes, offset + 2)?)
            .map_err(|_| CensusDataError::Metadata)?;
        if permissions > 7 {
            return Err(CensusDataError::Metadata);
        }
        let id = le_u32(bytes, offset + 4)?;
        let entry = match tag {
            0x01 if id == ACL_UNDEFINED_ID => {
                objects[0] = true;
                AclEntry::UserObject(permissions)
            }
            0x02 if id != ACL_UNDEFINED_ID => {
                named = true;
                maximum_uid = maximum_uid.max(id);
                AclEntry::NamedUser { uid: id, permissions }
            }
            0x04 if id == ACL_UNDEFINED_ID => {
                objects[1] = true;
                AclEntry::GroupObject(permissions)
            }
            0x08 if id != ACL_UNDEFINED_ID => {
                named = true;
                maximum_gid = maximum_gid.max(id);
                AclEntry::NamedGroup { gid: id, permissions }
            }
            0x10 if id == ACL_UNDEFINED_ID => {
                mask = true;
                AclEntry::Mask(permissions)
            }
            0x20 if id == ACL_UNDEFINED_ID => {
                objects[2] = true;
                AclEntry::Other(permissions)
            }
            _ => return Err(CensusDataError::Metadata),
        };
        entries.push(entry);
    }
    if objects != [true; 3] || named && !mask {
        return Err(CensusDataError::Metadata);
    }
    // Core checks unique identities and typed tag/ID ordering. No second
    // portable ACL codec or normalization of hostile raw order is introduced.
    let capacity_bytes = entries.capacity().checked_mul(std::mem::size_of::<AclEntry>())
        .ok_or(CensusDataError::Capacity)?;
    let acl = Acl::new(entries)?;
    Ok(LinuxAclObservation { acl, maximum_uid, maximum_gid, capacity_bytes })
}

/// Reads only the actual root-ID semantics from a pinned capability xattr.
pub(crate) fn capability_root_id(bytes: &[u8]) -> Result<u32, CensusDataError> {
    let header = le_u32(bytes, 0)?;
    let revision = header & 0xff00_0000;
    if header & 0x00ff_fffe != 0 {
        return Err(CensusDataError::Metadata);
    }
    match (revision, bytes.len()) {
        (0x0100_0000, 12) | (0x0200_0000, 20) => Ok(0),
        (0x0300_0000, 24) => {
            let root = le_u32(bytes, 20)?;
            if root == u32::MAX {
                return Err(CensusDataError::Metadata);
            }
            Ok(root)
        }
        _ => Err(CensusDataError::Metadata),
    }
}

fn le_u16(bytes: &[u8], offset: usize) -> Result<u16, CensusDataError> {
    let field: [u8; 2] = bytes.get(offset..offset + 2)
        .and_then(|field| field.try_into().ok()).ok_or(CensusDataError::Metadata)?;
    Ok(u16::from_le_bytes(field))
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32, CensusDataError> {
    let field: [u8; 4] = bytes.get(offset..offset + 4)
        .and_then(|field| field.try_into().ok()).ok_or(CensusDataError::Metadata)?;
    Ok(u32::from_le_bytes(field))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arena_source_lends_the_original_without_an_object_copy() {
        let mut arena = CensusObjectArena::default();
        let bytes = b"canonical content".to_vec();
        let descriptor = arena.capture_object(PortableMediaType::Content, bytes).unwrap();

        let reader = arena.open(&descriptor).unwrap();

        assert_eq!(*reader.get_ref(), b"canonical content");
    }

    #[test]
    fn capability_revision_width_and_flags_are_not_guessed() {
        let mut bytes = [0_u8; 24];
        bytes[..4].copy_from_slice(&0x0300_0001_u32.to_le_bytes());
        bytes[20..].copy_from_slice(&42_u32.to_le_bytes());

        assert_eq!(capability_root_id(&bytes).unwrap(), 42);
        assert!(capability_root_id(&bytes[..20]).is_err());

        bytes[1] = 1;

        assert!(capability_root_id(&bytes).is_err());
    }

    #[test]
    fn native_metadata_failure_is_borrowed_before_later_inode_debt() {
        let mut capture = CensusMetadataCapture::default();
        capture.attempted = true;
        capture.list_sizes[0] = Some(Err(rustix::io::Errno::ACCESS));
        capture.outcome = Some(Err(CensusDataError::NativeObservation));
        capture.inode[1] = Some(Err(rustix::io::Errno::IO));

        assert_eq!(capture.native_failure(), Some(&rustix::io::Errno::ACCESS));
        assert!(matches!(capture.failure(), Some(CensusDataError::NativeObservation)));
        assert!(capture.metadata().is_err());
        assert!(capture.summary().is_err());
    }

    #[test]
    fn native_directory_failure_keeps_its_first_errno_and_closed_names() {
        let mut capture = CensusDirectoryNames::prepare().unwrap();
        capture.attempted = true;
        capture.read_failure = Some(rustix::io::Errno::IO);
        capture.outcome = Some(Err(CensusDataError::NativeObservation));
        capture.stat[1] = Some(Err(rustix::io::Errno::BADF));

        assert_eq!(capture.native_failure(), Some(&rustix::io::Errno::IO));
        assert!(capture.names().is_err());
        assert!(capture.failure().is_some());
        assert!(capture.capacity_bytes().unwrap() >= 64 * 1024);
    }

    #[test]
    fn content_action_failure_precedes_independent_post_errno() {
        let mut capture = CensusContentCapture::default();
        capture.attempted = true;
        capture.outcome = Some(Err(CensusDataError::Capacity));
        capture.inode[1] = Some(Err(rustix::io::Errno::IO));
        capture.postcheck = Some(Err(CensusDataError::NativeObservation));

        assert!(capture.failure().unwrap().downcast_ref::<CensusDataError>()
            .is_some_and(|error| matches!(error, CensusDataError::Capacity)));
        assert_eq!(capture.postcheck_debt(), Some(&rustix::io::Errno::IO));
        assert!(capture.bytes().is_err());
    }

    #[test]
    fn changed_metadata_post_is_not_a_missing_cause_or_healthy_model() {
        let mut capture = CensusMetadataCapture::default();
        capture.attempted = true;
        capture.postcheck = Some(Err(CensusDataError::Changed));

        assert!(matches!(capture.failure(), Some(CensusDataError::Changed)));
        assert!(capture.metadata().is_err());
        assert!(capture.transfer_metadata().is_err());
    }

    #[test]
    fn node_native_action_errno_precedes_terminal_inode_debt() {
        let mut state = CensusWalkState::default();
        let index = state.prepare_node(Path::new("")).unwrap();
        state.records[index].inode[2] = Some(Err(rustix::io::Errno::IO));
        state.records[index].terminal_inode = Some(Err(rustix::io::Errno::ACCESS));
        state.retain_node_result(index, Err(CensusDataError::NativeObservation));

        let cause = state.failure().unwrap();

        assert_eq!(cause.downcast_ref::<rustix::io::Errno>(), Some(&rustix::io::Errno::IO));
    }

    #[test]
    fn node_semantic_action_failure_precedes_later_inode_errno() {
        let mut state = CensusWalkState::default();
        let index = state.prepare_node(Path::new("")).unwrap();
        state.records[index].inode[2] = Some(Err(rustix::io::Errno::IO));
        state.retain_node_result(index, Err(CensusDataError::Capacity));

        let cause = state.failure().unwrap();

        assert!(matches!(cause.downcast_ref::<CensusDataError>(), Some(CensusDataError::Capacity)));
    }

    #[test]
    fn child_beyond_depth_bound_refuses_before_node_or_path_creation() {
        let mut state = CensusWalkState::default();
        for node in 0..=super::super::MAXIMUM_DEPTH {
            state.directories.push(CensusDirectoryFrame {
                node,
                names: Vec::new().into_iter(),
                parent: None,
            });
        }
        let name = PathName::new(b"child".to_vec()).unwrap();

        let result = state.prepare_child(0, &name);

        assert!(matches!(result, Err(CensusDataError::Capacity)));
        assert!(state.records.is_empty());
    }
}
